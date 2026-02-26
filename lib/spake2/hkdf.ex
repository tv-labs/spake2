defmodule Spake2.HKDF do
  @moduledoc """
  HKDF (HMAC-based Key Derivation Function) per RFC 5869.

  Two-step process:
  1. **Extract** — condenses input keying material into a pseudorandom key (PRK)
  2. **Expand** — expands PRK into output keying material of desired length
  """

  @type hash_algorithm :: :sha256 | :sha384 | :sha512

  @doc """
  Derives `length` bytes of keying material from `ikm`.

  ## Options

    * `:hash` - hash algorithm (default `:sha256`)
    * `:salt` - optional salt (default: zero-filled bytes matching hash length)
    * `:info` - optional context/application info (default: `""`)
  """
  @spec derive(binary(), non_neg_integer(), keyword()) :: binary()
  def derive(ikm, length, opts \\ []) when is_binary(ikm) and length > 0 do
    hash = Keyword.get(opts, :hash, :sha256)
    salt = Keyword.get(opts, :salt, <<>>)
    info = Keyword.get(opts, :info, <<>>)

    ikm
    |> extract(salt, hash)
    |> expand(info, length, hash)
  end

  @doc """
  Extract step: condenses `ikm` into a pseudorandom key using HMAC.

  `PRK = HMAC-Hash(salt, ikm)`
  """
  @spec extract(binary(), binary(), hash_algorithm()) :: binary()
  def extract(ikm, salt \\ <<>>, hash \\ :sha256) do
    salt =
      case salt do
        <<>> -> :binary.copy(<<0>>, hash_length(hash))
        s -> s
      end

    :crypto.mac(:hmac, hash, salt, ikm)
  end

  @doc """
  Expand step: expands `prk` into `length` bytes of output keying material.

  `T(i) = HMAC-Hash(PRK, T(i-1) || info || i)`
  """
  @spec expand(binary(), binary(), non_neg_integer(), hash_algorithm()) :: binary()
  def expand(prk, info \\ <<>>, length, hash \\ :sha256)
      when is_binary(prk) and length > 0 do
    hash_len = hash_length(hash)
    n = ceil(length / hash_len)

    if n > 255,
      do: raise(ArgumentError, "HKDF expand: requested length too large (max #{255 * hash_len})")

    1..n
    |> Enum.reduce({<<>>, <<>>}, fn i, {prev_t, acc} ->
      t = :crypto.mac(:hmac, hash, prk, <<prev_t::binary, info::binary, i::8>>)
      {t, <<acc::binary, t::binary>>}
    end)
    |> elem(1)
    |> binary_part(0, length)
  end

  defp hash_length(:sha256), do: 32
  defp hash_length(:sha384), do: 48
  defp hash_length(:sha512), do: 64
end
