# frozen_string_literal: true

require 'digest'

module Merkle
  # Encapsulates the hash utilities used across the library
  class Hashing < Encoder
    # Core hash utility
    # Renamed to .digest as .hash is reserved in Ruby
    def digest(left, right = nil)
      @algorithm.hexdigest(encode(left, right))
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
