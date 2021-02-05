# frozen_string_literal: true

require 'digest'

module Merkle
  # Encapsulates the hash utilities used across the library
  class Hashing < Encoder
    attr_reader :algorithm

    # Core hash utility
    # Renamed to .digest as .hash is reserved in Ruby
    def digest(left, right = nil)
      @algorithm.hexdigest(encode(left, right))
    end

    def multi_digest(signed_digests, start)
      raise EmptyPathException if signed_digests.empty?
      return signed_digests[0][1] if signed_digests.size == 1

      signed_digests = signed_digests.dup
      i = start
      loop do
        break if signed_digests.size == 1

        if signed_digests[i][0] == 1
          new_sign = i == 0 ? 1 : signed_digests[i + 1][0]
          new_hash = digest(signed_digests[i][1], signed_digests[i + 1][1])
          move = 1
        else
          new_sign = signed_digests[i - 1][0]
          new_hash = digest(signed_digests[i - 1][1], signed_digests[i][1])
          move = -1
        end
        signed_digests[i] = [new_sign, new_hash]
        signed_digests.delete_at(i + move)
        i -= move if move < 0
      end

      signed_digests[0][1]
    end

    private

    def initialize(algorithm: Digest::SHA256, encoding: 'utf-8', security: true)
      unless algorithm.respond_to?(:hexdigest)
        raise UnsupportedHashType.new("Hash algorithm #{algorithm} not support #hexdigest")
      end

      @algorithm = algorithm
      super(encoding: encoding, security: security)
    end
  end
end
