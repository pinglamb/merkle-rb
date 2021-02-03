# frozen_string_literal: true

require 'digest'

module Merkle
  # Encapsulates the hash utilities used across the library
  class Hashing
    # Core hash utility
    # Renamed to .digest as .hash is reserved in Ruby
    def digest(left)
      Digest::SHA256.hexdigest(left)
    end
  end
end
