defmodule Spake2.Ed25519 do
  @moduledoc """
  Ed25519 twisted Edwards curve point arithmetic for SPAKE2.

  Provides point addition, scalar multiplication, and encoding/decoding
  on the Ed25519 curve (-x^2 + y^2 = 1 + d*x^2*y^2 over GF(2^255-19)).

  Based on the approach from the `ed25519` hex package, with operations
  made public for use in the SPAKE2 protocol.
  """

  alias Spake2.Ed25519.DecodeError

  import Bitwise

  @typedoc "A point on the Ed25519 curve as {x, y} affine coordinates."
  @type point :: {integer(), integer()}

  # Field prime: 2^255 - 19
  @p 57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_949

  # Group order (prime order of the base point subgroup)
  @l 7_237_005_577_332_262_213_973_186_563_042_994_240_857_116_359_379_907_606_001_950_938_285_454_250_989

  # Curve parameter d
  @d -4_513_249_062_541_557_337_682_894_930_092_624_173_785_641_285_191_125_241_628_941_591_882_900_924_598_840_740

  # sqrt(-1) mod p
  @i 19_681_161_376_707_505_956_807_079_304_988_542_015_446_066_515_923_890_162_744_021_073_123_829_784_752

  # Bitmask for clearing the sign bit (bit 255): 2^255 - 1
  @low_255_bits (1 <<< 255) - 1

  # Base point (generator)
  @base {15_112_221_349_535_400_772_501_151_409_588_531_511_454_012_693_041_857_206_046_113_283_949_847_762_202,
         46_316_835_694_926_478_169_428_394_003_475_163_141_307_993_866_256_225_615_783_033_603_165_251_855_960}

  # Identity element (neutral point)
  @identity {0, 1}

  @doc "Returns the field prime p = 2^255 - 19."
  def p, do: @p

  @doc "Returns the group order l."
  def l, do: @l

  @doc "Returns the Ed25519 base point (generator)."
  def base_point, do: @base

  @doc "Returns the identity point {0, 1}."
  def identity, do: @identity

  @doc "Adds two points on the Ed25519 twisted Edwards curve."
  @spec add(point(), point()) :: point()
  def add({x1, y1}, {x2, y2}) do
    x = (x1 * y2 + x2 * y1) * inv(1 + @d * x1 * x2 * y1 * y2)
    y = (y1 * y2 + x1 * x2) * inv(1 - @d * x1 * x2 * y1 * y2)
    {mod(x, @p), mod(y, @p)}
  end

  @doc "Negates a point (reflects across the y-axis)."
  @spec negate(point()) :: point()
  def negate({x, y}), do: {mod(@p - x, @p), y}

  @doc "Subtracts point `q` from point `p`."
  @spec subtract(point(), point()) :: point()
  def subtract(p1, p2), do: add(p1, negate(p2))

  @doc """
  Multiplies a point by a scalar using a Montgomery ladder.

  Processes a fixed 256 bits regardless of the scalar value, performing the
  same number of point additions and doublings for every input. This avoids
  leaking scalar bits through timing side-channels.

  Note: The underlying big-integer field arithmetic in Erlang/OTP is not
  guaranteed to be constant-time, but the ladder eliminates the most
  significant leak (variable operation count based on scalar Hamming weight).
  """
  @spec scalar_mult(integer(), point()) :: point()
  def scalar_mult(scalar, point) do
    scalar = mod(scalar, @l)

    # Montgomery ladder: fixed 255 iterations (bit length of l)
    255..0//-1
    |> Enum.reduce({@identity, point}, fn i, {r0, r1} ->
      bit = scalar |> bsr(i) |> band(1)
      {r0, r1} = cswap(bit, r0, r1)
      r1 = add(r0, r1)
      r0 = add(r0, r0)
      cswap(bit, r0, r1)
    end)
    |> elem(0)
  end

  defp cswap(0, a, b), do: {a, b}
  defp cswap(1, a, b), do: {b, a}

  @doc "Encodes a point to 32 bytes (compressed Ed25519 format)."
  @spec encode(point()) :: binary()
  def encode({x, y}) do
    val =
      y
      |> band(@low_255_bits)
      |> bor((x &&& 1) <<< 255)

    <<val::little-size(256)>>
  end

  @doc "Decodes 32 bytes (compressed Ed25519) to a curve point."
  @spec decode(binary()) :: {:ok, point()} | {:error, atom()}
  def decode(<<n::little-size(256)>>) do
    xc = n |> bsr(255)
    y = n |> band(@low_255_bits)
    x = xrecover(y)

    point =
      case x &&& 1 do
        ^xc -> {x, y}
        _ -> {@p - x, y}
      end

    if on_curve?(point), do: {:ok, point}, else: {:error, DecodeError.exception(:not_on_curve)}
  end

  def decode(_), do: {:error, DecodeError.exception(:invalid_encoding)}

  @doc "Decodes 32 bytes to a curve point, raising on error."
  @spec decode!(binary()) :: point()
  def decode!(bytes) do
    case decode(bytes) do
      {:ok, point} -> point
      {:error, exception} -> raise exception
    end
  end

  @doc "Returns true if the point lies on the Ed25519 curve."
  @spec on_curve?(point()) :: boolean()
  def on_curve?({x, y}) do
    mod(-x * x + y * y - 1 - @d * x * x * y * y, @p) == 0
  end

  @doc """
  Returns true if the point has small order (divides the cofactor 8).

  A low-order point contributes nothing to the DH shared secret after
  cofactor clearing and MUST be rejected when received from a peer.
  """
  @spec low_order?(point()) :: boolean()
  def low_order?(point) do
    scalar_mult(8, point) == @identity
  end

  @doc "Reduces a 64-byte little-endian integer modulo the group order l."
  @spec sc_reduce(binary()) :: integer()
  def sc_reduce(<<n::little-size(512)>>) do
    mod(n, @l)
  end

  # Recover x coordinate from y
  defp xrecover(y) do
    xx = (y * y - 1) * inv(@d * y * y + 1)
    x = expmod(xx, div(@p + 3, 8), @p)

    x =
      case mod(x * x - xx, @p) do
        0 -> x
        _ -> mod(x * @i, @p)
      end

    case mod(x, 2) do
      0 -> @p - x
      _ -> x
    end
  end

  defp mod(0, _y), do: 0
  defp mod(x, y) when x > 0, do: rem(x, y)
  defp mod(x, y) when x < 0, do: rem(y + rem(x, y), y)

  defp expmod(b, e, m) when b > 0 do
    b |> :crypto.mod_pow(e, m) |> :binary.decode_unsigned()
  end

  defp expmod(b, e, m) do
    i = b |> abs() |> :crypto.mod_pow(e, m) |> :binary.decode_unsigned()

    cond do
      mod(e, 2) == 0 -> i
      i == 0 -> i
      true -> m - i
    end
  end

  defp inv(x), do: expmod(mod(x, @p), @p - 2, @p)
end
