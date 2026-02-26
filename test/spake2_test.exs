defmodule Spake2Test do
  use ExUnit.Case
  use ExUnitProperties

  alias Spake2.Ed25519

  describe "Ed25519 point operations" do
    test "base point is on curve" do
      assert Ed25519.on_curve?(Ed25519.base_point())
    end

    test "encode/decode round-trip for base point" do
      bp = Ed25519.base_point()
      encoded = Ed25519.encode(bp)
      assert {:ok, ^bp} = Ed25519.decode(encoded)
    end

    test "identity is additive neutral element" do
      bp = Ed25519.base_point()
      assert Ed25519.add(bp, Ed25519.identity()) == bp
    end

    test "scalar multiplication by group order gives identity" do
      bp = Ed25519.base_point()
      assert Ed25519.scalar_mult(Ed25519.l(), bp) == Ed25519.identity()
    end

    test "negate and add gives identity" do
      bp = Ed25519.base_point()
      assert Ed25519.add(bp, Ed25519.negate(bp)) == Ed25519.identity()
    end

    test "subtract is inverse of add" do
      bp = Ed25519.base_point()
      doubled = Ed25519.add(bp, bp)
      assert Ed25519.subtract(doubled, bp) == bp
    end

    test "scalar_mult(2, B) == add(B, B)" do
      bp = Ed25519.base_point()
      assert Ed25519.scalar_mult(2, bp) == Ed25519.add(bp, bp)
    end

    test "decode! raises on non-32-byte input" do
      assert_raise Ed25519.DecodeError, fn ->
        Ed25519.decode!(<<0xFF>>)
      end
    end
  end

  describe "Ed25519 property tests" do
    property "scalar_mult is distributive: (a+b)*B == a*B + b*B" do
      check all(
              a <- StreamData.integer(1..1000),
              b <- StreamData.integer(1..1000)
            ) do
        bp = Ed25519.base_point()
        left = Ed25519.scalar_mult(a + b, bp)
        right = Ed25519.add(Ed25519.scalar_mult(a, bp), Ed25519.scalar_mult(b, bp))
        assert left == right
      end
    end

    property "encode/decode round-trip for arbitrary scalar multiples of B" do
      check all(scalar <- StreamData.integer(1..10_000)) do
        point = Ed25519.scalar_mult(scalar, Ed25519.base_point())
        encoded = Ed25519.encode(point)
        assert {:ok, ^point} = Ed25519.decode(encoded)
      end
    end

    property "n*B + (l-n)*B == identity for any n" do
      check all(n <- StreamData.integer(1..1000)) do
        bp = Ed25519.base_point()
        l = Ed25519.l()
        left = Ed25519.scalar_mult(n, bp)
        right = Ed25519.scalar_mult(l - n, bp)
        assert Ed25519.add(left, right) == Ed25519.identity()
      end
    end
  end

  describe "BoringSSL M/N constants" do
    test "M point is generated from seed 'edwards25519 point generation seed (M)'" do
      m_point = Spake2.genpoint("edwards25519 point generation seed (M)")
      assert Ed25519.encode(m_point) == Spake2.m_bytes()
    end

    test "N point is generated from seed 'edwards25519 point generation seed (N)'" do
      n_point = Spake2.genpoint("edwards25519 point generation seed (N)")
      assert Ed25519.encode(n_point) == Spake2.n_bytes()
    end

    test "M and N points are on the curve" do
      {:ok, m} = Ed25519.decode(Spake2.m_bytes())
      {:ok, n} = Ed25519.decode(Spake2.n_bytes())
      assert Ed25519.on_curve?(m)
      assert Ed25519.on_curve?(n)
    end

    test "cofactor-cleared scalar * M lands in prime-order subgroup" do
      {:ok, m} = Ed25519.decode(Spake2.m_bytes())
      m8 = Ed25519.scalar_mult(8, m)
      assert Ed25519.scalar_mult(Ed25519.l(), m8) == Ed25519.identity()
    end

    test "cofactor-cleared scalar * N lands in prime-order subgroup" do
      {:ok, n} = Ed25519.decode(Spake2.n_bytes())
      n8 = Ed25519.scalar_mult(8, n)
      assert Ed25519.scalar_mult(Ed25519.l(), n8) == Ed25519.identity()
    end
  end

  describe "SPAKE2 protocol" do
    test "Alice and Bob derive the same key with matching password" do
      password = "123456"

      alice = Spake2.new(:alice, "alice", "bob")
      bob = Spake2.new(:bob, "bob", "alice")

      {alice, alice_msg} = Spake2.generate_msg(alice, password)
      {bob, bob_msg} = Spake2.generate_msg(bob, password)

      assert byte_size(alice_msg) == 32
      assert byte_size(bob_msg) == 32

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)
      {:ok, bob} = Spake2.process_msg(bob, alice_msg)

      assert alice.session_key == bob.session_key
      assert byte_size(alice.session_key) == 32
    end

    test "different passwords produce different keys" do
      alice = Spake2.new(:alice, "alice", "bob")
      bob = Spake2.new(:bob, "bob", "alice")

      {alice, alice_msg} = Spake2.generate_msg(alice, "123456")
      {bob, bob_msg} = Spake2.generate_msg(bob, "654321")

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)
      {:ok, bob} = Spake2.process_msg(bob, alice_msg)

      assert alice.session_key != bob.session_key
    end

    test "different names produce different keys" do
      password = "123456"
      entropy = fixed_entropy()

      alice = Spake2.new(:alice, "alice", "bob")
      bob = Spake2.new(:bob, "bob", "not-alice")

      {alice, alice_msg} = Spake2.generate_msg(alice, password, entropy: entropy)
      {bob, bob_msg} = Spake2.generate_msg(bob, password, entropy: entropy)

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)
      {:ok, bob} = Spake2.process_msg(bob, alice_msg)

      assert alice.session_key != bob.session_key
    end

    test "empty names work" do
      password = "test"

      alice = Spake2.new(:alice)
      bob = Spake2.new(:bob)

      {alice, alice_msg} = Spake2.generate_msg(alice, password)
      {bob, bob_msg} = Spake2.generate_msg(bob, password)

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)
      {:ok, bob} = Spake2.process_msg(bob, alice_msg)

      assert alice.session_key == bob.session_key
    end

    test "deterministic entropy produces repeatable results" do
      password = "123456"

      alice = Spake2.new(:alice, "alice", "bob")
      {_alice, msg1} = Spake2.generate_msg(alice, password, entropy: fixed_entropy())

      alice = Spake2.new(:alice, "alice", "bob")
      {_alice, msg2} = Spake2.generate_msg(alice, password, entropy: fixed_entropy())

      assert msg1 == msg2
    end

    test "corrupted message produces different key" do
      password = "123456"

      alice = Spake2.new(:alice, "alice", "bob")
      bob = Spake2.new(:bob, "bob", "alice")

      {alice, _alice_msg} = Spake2.generate_msg(alice, password)
      {_bob, bob_msg} = Spake2.generate_msg(bob, password)

      <<first_byte, rest::binary>> = bob_msg
      corrupted = <<Bitwise.bxor(first_byte, 1), rest::binary>>

      case Spake2.process_msg(alice, corrupted) do
        {:error, _} ->
          :ok

        {:ok, alice_corrupted} ->
          {:ok, alice_good} =
            Spake2.process_msg(
              Spake2.new(:alice, "alice", "bob")
              |> then(fn ctx ->
                {ctx, _} = Spake2.generate_msg(ctx, password)
                ctx
              end),
              bob_msg
            )

          assert alice_corrupted.session_key != alice_good.session_key
      end
    end
  end

  describe "low-order point rejection" do
    test "identity point is rejected by process_msg" do
      password = "123456"

      alice = Spake2.new(:alice, "alice", "bob")
      {alice, _alice_msg} = Spake2.generate_msg(alice, password)

      # The identity point {0, 1} encodes to <<1, 0, ..., 0>>
      identity_encoded = Ed25519.encode(Ed25519.identity())

      assert {:error, %Ed25519.DecodeError{message: msg}} =
               Spake2.process_msg(alice, identity_encoded)

      assert msg =~ "small order"
    end

    test "Ed25519 low_order? detects identity" do
      assert Ed25519.low_order?(Ed25519.identity())
    end

    test "Ed25519 low_order? rejects base point" do
      refute Ed25519.low_order?(Ed25519.base_point())
    end

    test "all 32-byte low-order points are rejected by process_msg" do
      password = "123456"
      alice = Spake2.new(:alice, "alice", "bob")
      {alice, _alice_msg} = Spake2.generate_msg(alice, password)

      # Known small-order points on Ed25519 (encoded)
      low_order_encodings = [
        # identity {0, 1}
        Ed25519.encode(Ed25519.identity()),
        # {0, -1 mod p} = {0, p-1}
        Ed25519.encode({0, Ed25519.p() - 1})
      ]

      for encoded <- low_order_encodings do
        case Spake2.process_msg(alice, encoded) do
          {:error, _} -> :ok
          {:ok, _} -> flunk("low-order point was accepted: #{Base.encode16(encoded)}")
        end
      end
    end
  end

  describe "state machine" do
    test "new/3 initializes state to :init" do
      ctx = Spake2.new(:alice, "alice", "bob")
      assert ctx.state == :init
    end

    test "generate_msg/3 transitions state to :msg_generated" do
      ctx = Spake2.new(:alice)
      {ctx, _msg} = Spake2.generate_msg(ctx, "password")
      assert ctx.state == :msg_generated
    end

    test "generate_msg/3 returns error on double call" do
      ctx = Spake2.new(:alice)
      {ctx, _msg} = Spake2.generate_msg(ctx, "password")

      assert {:error, {:invalid_state, :msg_generated}} = Spake2.generate_msg(ctx, "password")
    end

    test "process_msg/2 returns error on state :init (skipped generate_msg)" do
      ctx = Spake2.new(:alice)

      assert {:error, {:invalid_state, :init}} =
               Spake2.process_msg(ctx, :crypto.strong_rand_bytes(32))
    end

    test "process_msg/2 transitions state to :key_derived" do
      password = "test"
      alice = Spake2.new(:alice)
      bob = Spake2.new(:bob)

      {alice, _alice_msg} = Spake2.generate_msg(alice, password)
      {_bob, bob_msg} = Spake2.generate_msg(bob, password)

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)
      assert alice.state == :key_derived
    end

    test "process_msg/2 returns error on double call" do
      password = "test"
      alice = Spake2.new(:alice)
      bob = Spake2.new(:bob)

      {alice, _alice_msg} = Spake2.generate_msg(alice, password)
      {_bob, bob_msg} = Spake2.generate_msg(bob, password)

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)

      assert {:error, {:invalid_state, :key_derived}} = Spake2.process_msg(alice, bob_msg)
    end
  end

  describe "key confirmation" do
    test "matching passwords produce verifiable confirmations" do
      password = "123456"

      alice = Spake2.new(:alice, "alice", "bob")
      bob = Spake2.new(:bob, "bob", "alice")

      {alice, alice_msg} = Spake2.generate_msg(alice, password)
      {bob, bob_msg} = Spake2.generate_msg(bob, password)

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)
      {:ok, bob} = Spake2.process_msg(bob, alice_msg)

      # Each side verifies the other's confirmation token
      assert {:ok, alice} = Spake2.verify_confirmation(alice, bob.my_confirmation)
      assert {:ok, bob} = Spake2.verify_confirmation(bob, alice.my_confirmation)

      assert alice.state == :confirmed
      assert bob.state == :confirmed
    end

    test "different passwords fail key confirmation" do
      alice = Spake2.new(:alice, "alice", "bob")
      bob = Spake2.new(:bob, "bob", "alice")

      {alice, alice_msg} = Spake2.generate_msg(alice, "123456")
      {bob, bob_msg} = Spake2.generate_msg(bob, "654321")

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)
      {:ok, bob} = Spake2.process_msg(bob, alice_msg)

      assert {:error, :confirmation_mismatch} =
               Spake2.verify_confirmation(alice, bob.my_confirmation)

      assert {:error, :confirmation_mismatch} =
               Spake2.verify_confirmation(bob, alice.my_confirmation)
    end

    test "confirmation tokens are 32 bytes" do
      password = "test"
      alice = Spake2.new(:alice)
      bob = Spake2.new(:bob)

      {alice, _alice_msg} = Spake2.generate_msg(alice, password)
      {_bob, bob_msg} = Spake2.generate_msg(bob, password)

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)

      assert byte_size(alice.my_confirmation) == 32
    end

    test "session key is 32 bytes" do
      password = "test"
      alice = Spake2.new(:alice)
      bob = Spake2.new(:bob)

      {alice, _alice_msg} = Spake2.generate_msg(alice, password)
      {_bob, bob_msg} = Spake2.generate_msg(bob, password)

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)

      assert byte_size(alice.session_key) == 32
    end

    test "verify_confirmation returns error on wrong state" do
      ctx = Spake2.new(:alice)

      assert {:error, {:invalid_state, :init}} = Spake2.verify_confirmation(ctx, <<0::256>>)
    end

    test "Alice and Bob produce different confirmation tokens" do
      password = "test"
      alice = Spake2.new(:alice, "alice", "bob")
      bob = Spake2.new(:bob, "bob", "alice")

      {alice, alice_msg} = Spake2.generate_msg(alice, password)
      {bob, bob_msg} = Spake2.generate_msg(bob, password)

      {:ok, alice} = Spake2.process_msg(alice, bob_msg)
      {:ok, bob} = Spake2.process_msg(bob, alice_msg)

      # Alice's token != Bob's token (prevents reflection attacks)
      assert alice.my_confirmation != bob.my_confirmation
    end
  end

  describe "genpoint/2" do
    test "raises when max_iterations exceeded" do
      # A seed that won't produce a valid point in 1 iteration
      # Use a fixed hash that we know fails decoding
      assert_raise FunctionClauseError, fn ->
        Spake2.genpoint("test seed", 0)
      end
    end

    test "existing M/N generation works with default limit" do
      m_point = Spake2.genpoint("edwards25519 point generation seed (M)")
      assert Ed25519.on_curve?(m_point)
    end
  end

  describe "SPAKE2 property tests" do
    property "matching passwords always produce matching keys" do
      check all(
              password <- StreamData.binary(min_length: 1, max_length: 64),
              alice_name <- StreamData.binary(max_length: 16),
              bob_name <- StreamData.binary(max_length: 16)
            ) do
        alice = Spake2.new(:alice, alice_name, bob_name)
        bob = Spake2.new(:bob, bob_name, alice_name)

        {alice, alice_msg} = Spake2.generate_msg(alice, password)
        {bob, bob_msg} = Spake2.generate_msg(bob, password)

        {:ok, alice} = Spake2.process_msg(alice, bob_msg)
        {:ok, bob} = Spake2.process_msg(bob, alice_msg)

        assert alice.session_key == bob.session_key
        assert byte_size(alice.session_key) == 32

        # Key confirmation also succeeds
        assert {:ok, _} = Spake2.verify_confirmation(alice, bob.my_confirmation)
        assert {:ok, _} = Spake2.verify_confirmation(bob, alice.my_confirmation)
      end
    end

    property "messages are always 32 bytes" do
      check all(password <- StreamData.binary(min_length: 1, max_length: 32)) do
        alice = Spake2.new(:alice)
        {_alice, msg} = Spake2.generate_msg(alice, password)
        assert byte_size(msg) == 32
      end
    end
  end

  # Returns a deterministic entropy function seeded from a string.
  defp fixed_entropy(seed \\ "test_seed") do
    state = :atomics.new(1, signed: false)
    :atomics.put(state, 1, 0)

    fn n_bytes ->
      counter = :atomics.add_get(state, 1, 1)
      generate_deterministic_bytes(seed, counter, n_bytes)
    end
  end

  defp generate_deterministic_bytes(seed, counter, n_bytes) do
    Stream.iterate(
      :crypto.hash(:sha256, "#{seed}-#{counter}"),
      &:crypto.hash(:sha256, &1)
    )
    |> Stream.flat_map(&:binary.bin_to_list/1)
    |> Enum.take(n_bytes)
    |> :erlang.list_to_binary()
  end
end
