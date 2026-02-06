defmodule Spake2 do
  @external_resource Path.join([__DIR__, "..", "README.md"])

  @moduledoc @external_resource
             |> File.read!()
             |> String.split("<!-- MDOC -->")
             |> Enum.fetch!(1)

  alias Spake2.Ed25519

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
    :my_msg
  ]

  @type t :: %__MODULE__{}

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
  @spec generate_msg(t(), binary(), keyword()) :: {t(), binary()}
  def generate_msg(%__MODULE__{} = ctx, password, opts \\ []) when is_binary(password) do
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

    ctx = %{ctx | private_key: private_key, password_hash: password_hash, pw_scalar: pw_scalar, my_msg: my_msg}
    {ctx, my_msg}
  end

  @doc """
  Processes the peer's SPAKE2 message and derives the shared key.

  Returns `{:ok, shared_key}` where `shared_key` is a 64-byte binary (SHA-512 output),
  or `{:error, exception}` if the peer's message is invalid.
  """
  @spec process_msg(t(), binary()) :: {:ok, binary()} | {:error, Exception.t()}
  def process_msg(%__MODULE__{} = ctx, their_msg) when byte_size(their_msg) == 32 do
    with {:ok, their_blinded} <- Ed25519.decode(their_msg),
         :ok <- reject_low_order(their_blinded) do
      # Unmask: Q = Q* - pw * their_mask
      their_mask = Ed25519.scalar_mult(ctx.pw_scalar, their_mask_point(ctx.role))
      their_unmasked = Ed25519.subtract(their_blinded, their_mask)

      # DH shared secret: K = private_key * Q
      dh_shared = Ed25519.scalar_mult(ctx.private_key, their_unmasked) |> Ed25519.encode()

      {:ok, transcript_hash(ctx, their_msg, dh_shared)}
    end
  end

  @doc """
  Generates an Ed25519 point from a seed using BoringSSL's algorithm.

  Repeatedly SHA-256 hashes the seed until finding a valid Ed25519 point.
  Used to generate the M and N constants.
  """
  @spec genpoint(binary()) :: Ed25519.point()
  def genpoint(seed) when is_binary(seed) do
    hash = :crypto.hash(:sha256, seed)

    case Ed25519.decode(hash) do
      {:ok, point} -> point
      {:error, _} -> genpoint(hash)
    end
  end

  # Password scalar: SHA-512 reduced mod l, then bottom 3 bits cleared.
  # The bit-clearing is a BoringSSL compat hack — adds multiples of l
  # so the scalar is divisible by the cofactor 8.
  defp password_scalar(password_hash) do
    scalar = Ed25519.sc_reduce(password_hash)
    l = Ed25519.l()
    scalar = if (scalar &&& 1) == 1, do: scalar + l, else: scalar
    scalar = if (scalar &&& 2) == 2, do: scalar + 2 * l, else: scalar
    if (scalar &&& 4) == 4, do: scalar + 4 * l, else: scalar
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
