# frozen_string_literal: true

module Merkle
  class Encoder
    def encode(left, right = nil)
      prefix_0, prefix_1 = @security ? ["\x00", "\x01"] : ['', '']

      if right.nil?
        (prefix_0 + left).force_encoding(@encoding)
      else
        (prefix_1 + left + prefix_1 + right).force_encoding(@encoding)
      end
    end

    private

    def initialize(encoding: 'utf-8', security: true)
      begin
        @encoding = Encoding.find(encoding)
      rescue ArgumentError
        raise UnsupportedEncoding.new("Encoding type #{encoding} is not supported")
      end

      @security = security
    end
  end
end
