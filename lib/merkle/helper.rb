# frozen_string_literal: true

module Merkle
  class Helper
    class << self
      # Additive decomposition in decreasing powers of 2
      # Given a positive integer uniquely decomposed as
      # ``2 ^ p_m + ... + 2 ^ p_1, p_m > ... > p_1 >= 0``
      # then the tuple *(p_m, ..., p_1)* is returned
      # :Example:
      # >>> 45 == 2 ** 5 + 2 ** 3 + 2 ** 2 + 1
      # True
      # >>>
      # >>> decompose(45)
      # (5, 3, 2, 0)
      def decompose(num)
        powers = []
        power = 0
        i = 1
        while i <= num
          powers << power if i & num > 0
          i <<= 1
          power += 1
        end
        powers.reverse
      end
    end
  end
end
