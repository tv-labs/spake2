defmodule Spake2.HKDFTest do
  use ExUnit.Case

  alias Spake2.HKDF

  # RFC 5869 test vectors
  # https://www.rfc-editor.org/rfc/rfc5869#appendix-A

  describe "RFC 5869 test vectors" do
    test "Test Case 1 — basic SHA-256" do
      ikm = Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
      salt = Base.decode16!("000102030405060708090A0B0C")
      info = Base.decode16!("F0F1F2F3F4F5F6F7F8F9")
      l = 42

      expected_prk =
        Base.decode16!("077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5")

      expected_okm =
        Base.decode16!(
          "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865"
        )

      prk = HKDF.extract(ikm, salt, :sha256)
      assert prk == expected_prk

      okm = HKDF.expand(prk, info, l, :sha256)
      assert okm == expected_okm

      # Also test the combined derive
      assert HKDF.derive(ikm, l, salt: salt, info: info) == expected_okm
    end

    test "Test Case 2 — longer inputs SHA-256" do
      ikm =
        Base.decode16!(
          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
        )

      salt =
        Base.decode16!(
          "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
        )

      info =
        Base.decode16!(
          "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
        )

      l = 82

      expected_prk =
        Base.decode16!("06A6B88C5853361A06104C9CEB35B45CEF760014904671014A193F40C15FC244")

      expected_okm =
        Base.decode16!(
          "B11E398DC80327A1C8E7F78C596A49344F012EDA2D4EFAD8A050CC4C19AFA97C59045A99CAC7827271CB41C65E590E09DA3275600C2F09B8367793A9ACA3DB71CC30C58179EC3E87C14C01D5C1F3434F1D87"
        )

      prk = HKDF.extract(ikm, salt, :sha256)
      assert prk == expected_prk

      okm = HKDF.expand(prk, info, l, :sha256)
      assert okm == expected_okm
    end

    test "Test Case 3 — zero-length salt and info SHA-256" do
      ikm = Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
      salt = <<>>
      info = <<>>
      l = 42

      expected_prk =
        Base.decode16!("19EF24A32C717B167F33A91D6F648BDF96596776AFDB6377AC434C1C293CCB04")

      expected_okm =
        Base.decode16!(
          "8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8"
        )

      prk = HKDF.extract(ikm, salt, :sha256)
      assert prk == expected_prk

      okm = HKDF.expand(prk, info, l, :sha256)
      assert okm == expected_okm
    end
  end

  describe "derive/3" do
    test "derives key with default options" do
      key = HKDF.derive("some input keying material", 32)
      assert byte_size(key) == 32
    end

    test "derives different keys with different info strings" do
      ikm = "shared secret"
      key1 = HKDF.derive(ikm, 16, info: "encryption")
      key2 = HKDF.derive(ikm, 16, info: "authentication")
      assert key1 != key2
    end

    test "derives different lengths" do
      ikm = "shared secret"
      key16 = HKDF.derive(ikm, 16)
      key32 = HKDF.derive(ikm, 32)
      assert byte_size(key16) == 16
      assert byte_size(key32) == 32
      # Shorter key should be a prefix of the longer one (same PRK and info)
      assert key16 == binary_part(key32, 0, 16)
    end
  end
end
