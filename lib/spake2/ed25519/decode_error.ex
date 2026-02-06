defmodule Spake2.Ed25519.DecodeError do
  @moduledoc "Raised when an Ed25519 point cannot be decoded."

  defexception [:message]

  @impl true
  def exception(:not_on_curve), do: %__MODULE__{message: "point is not on the Ed25519 curve"}
  def exception(:invalid_encoding), do: %__MODULE__{message: "invalid Ed25519 point encoding (expected 32 bytes)"}
  def exception(:low_order_point), do: %__MODULE__{message: "received point has small order (not in prime-order subgroup)"}
end
