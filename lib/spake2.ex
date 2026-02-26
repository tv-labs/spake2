defmodule Spake2 do
  @external_resource "README.md"

  @moduledoc @external_resource
             |> File.read!()
             |> String.split("<!-- MDOC -->")
             |> Enum.fetch!(1)

  alias Spake2.Ed25519
  alias Spake2.HKDF

  import Bitwise

  # BoringSSL M and N constants (compressed Ed25519 points)
  # Generated from seeds "edwards25519 point generation seed (M)" and "(N)"
  @m_bytes Base.decode16!("5ADA7E4BF6DDD9ADB6626D32131C6B5C51A1E347A3478F53CFCF441B88EED12E")
  @n_bytes Base.decode16!("10E3DF0AE37D8E7A99B5FE74B44672103DBDDCBD06AF680D71329A11693BC778")

  @type role :: :alice | :bob

  defstruct [
    :role,
    :my_name,
    :their_name,
    :private_key,
    :password_hash,
    :pw_scalar,
    :my_msg,
    :transcript_key,
    :session_key,
    :my_confirmation,
    :their_confirmation,
    state: :init
  ]

  @type state :: :init | :msg_generated | :key_derived | :confirmed

  @type t :: %__MODULE__{
          role: role(),
          my_name: binary(),
          their_name: binary(),
          private_key: integer() | nil,
          password_hash: binary() | nil,
          pw_scalar: integer() | nil,
          my_msg: binary() | nil,
          transcript_key: binary() | nil,
          session_key: binary() | nil,
          my_confirmation: binary() | nil,
          their_confirmation: binary() | nil,
          state: state()
        }

  @doc "Returns the M point (compressed Ed25519 bytes)."
  def m_bytes, do: @m_bytes

  @doc "Returns the N point (compressed Ed25519 bytes)."
  def n_bytes, do: @n_bytes

  @doc "Creates a new SPAKE2 context for the given role."
  @spec new(role(), binary(), binary()) :: t()
  def new(role, my_name \\ <<>>, their_name \\ <<>>) when role in [:alice, :bob] do
    %__MODULE__{role: role, my_name: my_name, their_name: their_name}
  end

  @doc """
  Generates the SPAKE2 message to send to the peer.

  Returns `{updated_ctx, message_bytes}` where `message_bytes` is a 32-byte
  compressed Ed25519 point to send over the wire.

  ## Options

    * `:entropy` - a function `(non_neg_integer() -> binary())` for deterministic testing.
      Defaults to `:crypto.strong_rand_bytes/1`.
  """
  @spec generate_msg(t(), binary(), keyword()) ::
          {t(), binary()} | {:error, {:invalid_state, state()}}
  def generate_msg(ctx, password, opts \\ [])

  def generate_msg(%__MODULE__{state: :init} = ctx, password, opts) when is_binary(password) do
    entropy_f = Keyword.get(opts, :entropy, &:crypto.strong_rand_bytes/1)

    password_hash = :crypto.hash(:sha512, password)
    pw_scalar = password_scalar(password_hash)

    # Ephemeral key: 64 random bytes -> reduce mod l -> multiply by cofactor 8
    random_scalar = entropy_f.(64) |> Ed25519.sc_reduce()
    private_key = random_scalar * 8

    # P = private_key * B
    public_point = Ed25519.scalar_mult(private_key, Ed25519.base_point())

    # Mask: pw * M (Alice) or pw * N (Bob)
    my_mask = Ed25519.scalar_mult(pw_scalar, my_mask_point(ctx.role))

    # Blinded message: P* = P + mask
    my_msg = Ed25519.add(public_point, my_mask) |> Ed25519.encode()

    ctx = %{
      ctx
      | private_key: private_key,
        password_hash: password_hash,
        pw_scalar: pw_scalar,
        my_msg: my_msg,
        state: :msg_generated
    }

    {ctx, my_msg}
  end

  def generate_msg(%__MODULE__{state: state}, _password, _opts) when state != :init do
    {:error, {:invalid_state, state}}
  end

  @doc """
  Processes the peer's SPAKE2 message and derives the shared key.

  Returns `{:ok, updated_ctx}` where `updated_ctx` contains:

    * `session_key` - 32-byte session key derived via HKDF
    * `my_confirmation` - 32-byte token to send to the peer for key confirmation
    * `transcript_key` - 64-byte raw SHA-512 transcript hash (BoringSSL-compatible).
      Use this when interoperating with BoringSSL peers that derive their own keys
      from the raw output (e.g. Android ADB pairing).

  Use `verify_confirmation/2` with the peer's confirmation token to complete the
  handshake. Until confirmation succeeds, the session key should not be trusted.
  """
  @spec process_msg(t(), binary()) :: {:ok, t()} | {:error, Exception.t()}
  def process_msg(%__MODULE__{state: :msg_generated} = ctx, their_msg)
      when byte_size(their_msg) == 32 do
    with {:ok, their_blinded} <- Ed25519.decode(their_msg),
         :ok <- reject_low_order(their_blinded) do
      # Unmask: Q = Q* - pw * their_mask
      their_mask = Ed25519.scalar_mult(ctx.pw_scalar, their_mask_point(ctx.role))
      their_unmasked = Ed25519.subtract(their_blinded, their_mask)

      # Defense-in-depth: reject unmasked points with small order
      with :ok <- reject_low_order(their_unmasked) do
        # DH shared secret: K = private_key * Q
        dh_shared = Ed25519.scalar_mult(ctx.private_key, their_unmasked) |> Ed25519.encode()

        raw_key = transcript_hash(ctx, their_msg, dh_shared)
        {:ok, derive_keys(ctx, their_msg, raw_key)}
      end
    end
  end

  def process_msg(%__MODULE__{state: state}, _their_msg) do
    {:error, {:invalid_state, state}}
  end

  @doc """
  Verifies the peer's key confirmation token.

  After exchanging SPAKE2 messages, both sides send their `my_confirmation`
  token to the peer. This function checks that the peer's token matches the
  expected value, proving they derived the same key.

  Returns `{:ok, updated_ctx}` (state `:confirmed`) or `{:error, :confirmation_mismatch}`.
  Uses constant-time comparison to prevent timing attacks.
  """
  @spec verify_confirmation(t(), binary()) ::
          {:ok, t()} | {:error, :confirmation_mismatch | {:invalid_state, state()}}
  def verify_confirmation(%__MODULE__{state: :key_derived} = ctx, their_token)
      when is_binary(their_token) do
    if :crypto.hash_equals(ctx.their_confirmation, their_token) do
      {:ok, %{ctx | state: :confirmed}}
    else
      {:error, :confirmation_mismatch}
    end
  end

  def verify_confirmation(%__MODULE__{state: state}, _their_token) do
    {:error, {:invalid_state, state}}
  end

  @doc """
  Generates an Ed25519 point from a seed using BoringSSL's algorithm.

  Repeatedly SHA-256 hashes the seed until finding a valid Ed25519 point.
  Used to generate the M and N constants.
  """
  @spec genpoint(binary(), pos_integer()) :: Ed25519.point()
  def genpoint(seed, max_iterations \\ 100) when is_binary(seed) and max_iterations > 0 do
    hash = :crypto.hash(:sha256, seed)

    case Ed25519.decode(hash) do
      {:ok, point} -> point
      {:error, _} -> genpoint(hash, max_iterations - 1)
    end
  end

  # Derives session key and confirmation tokens from the raw transcript hash.
  # Uses HKDF with domain-separated info strings to prevent key reuse.
  # Separate confirmation keys for Alice and Bob prevent reflection attacks.
  defp derive_keys(ctx, their_msg, raw_key) do
    {alice_msg, bob_msg} =
      case ctx.role do
        :alice -> {ctx.my_msg, their_msg}
        :bob -> {their_msg, ctx.my_msg}
      end

    session_key = HKDF.derive(raw_key, 32, info: "SPAKE2 session key")
    alice_confirm_key = HKDF.derive(raw_key, 32, info: "SPAKE2 Alice confirm")
    bob_confirm_key = HKDF.derive(raw_key, 32, info: "SPAKE2 Bob confirm")

    confirmation_data = alice_msg <> bob_msg

    alice_confirmation = :crypto.mac(:hmac, :sha256, alice_confirm_key, confirmation_data)
    bob_confirmation = :crypto.mac(:hmac, :sha256, bob_confirm_key, confirmation_data)

    {my_confirmation, their_confirmation} =
      case ctx.role do
        :alice -> {alice_confirmation, bob_confirmation}
        :bob -> {bob_confirmation, alice_confirmation}
      end

    %{
      ctx
      | transcript_key: raw_key,
        session_key: session_key,
        my_confirmation: my_confirmation,
        their_confirmation: their_confirmation,
        state: :key_derived
    }
  end

  # Password scalar: SHA-512 reduced mod l, then bottom 3 bits cleared by
  # adding multiples of l. This matches BoringSSL's "password_scalar_hack"
  # (commit 696c13b) which adds kOrder to flip bits rather than masking.
  #
  # We CANNOT use `band(bnot(7))` because M and N are not in the prime-order
  # subgroup, so `k*l * M ≠ identity`. The scalar_mult does not reduce mod l,
  # so the actual numeric value of the scalar matters, not just its residue.
  defp password_scalar(password_hash) do
    scalar = Ed25519.sc_reduce(password_hash)
    l = Ed25519.l()
    scalar = if band(scalar, 1) == 1, do: scalar + l, else: scalar
    scalar = if band(scalar, 2) == 2, do: scalar + 2 * l, else: scalar
    if band(scalar, 4) == 4, do: scalar + 4 * l, else: scalar
  end

  defp reject_low_order(point) do
    if Ed25519.low_order?(point),
      do: {:error, Ed25519.DecodeError.exception(:low_order_point)},
      else: :ok
  end

  defp my_mask_point(:alice), do: Ed25519.decode!(@m_bytes)
  defp my_mask_point(:bob), do: Ed25519.decode!(@n_bytes)

  defp their_mask_point(:alice), do: Ed25519.decode!(@n_bytes)
  defp their_mask_point(:bob), do: Ed25519.decode!(@m_bytes)

  # SHA-512 transcript hash. Canonical order: alice first, then bob.
  # Each field is prefixed with its byte length as a little-endian uint64.
  defp transcript_hash(ctx, their_msg, dh_shared) do
    {alice_name, bob_name, alice_msg, bob_msg} =
      case ctx.role do
        :alice -> {ctx.my_name, ctx.their_name, ctx.my_msg, their_msg}
        :bob -> {ctx.their_name, ctx.my_name, their_msg, ctx.my_msg}
      end

    :crypto.hash(:sha512, [
      length_prefix(alice_name),
      length_prefix(bob_name),
      length_prefix(alice_msg),
      length_prefix(bob_msg),
      length_prefix(dh_shared),
      length_prefix(ctx.password_hash)
    ])
  end

  defp length_prefix(data) when is_binary(data) do
    <<byte_size(data)::little-64, data::binary>>
  end
end
