module Merkle
  class Challenge
    attr_reader :checksum, :subhash

    def audit?
      !@checksum.nil?
    end

    def consistency?
      !@subhash.nil?
    end

    private

    def initialize(checksum: nil, subhash: nil)
      if checksum && subhash.nil?
        @checksum = checksum
      elsif checksum.nil? && subhash
        @subhash = subhash
      else
        raise InvalidChallengeError
      end
    end
  end
end
