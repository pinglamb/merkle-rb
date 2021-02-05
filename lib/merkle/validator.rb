# frozen_string_literal: true

module Merkle
  class Validator
    attr_reader :proof

    def run(target: nil)
      raise NoProofError unless @proof
      raise NoTargetError unless target ||= @proof.commitment

      raise InvalidMerkleProof if @proof.proof_index == -1 && @proof.proof_path.empty?
      raise InvalidMerkleProof if target != @hashing.multi_hash(@proof.proof_path, @proof.proof_index)
    end

    private

    def initialize(proof)
      @proof = proof

      # Hashing configuration
      @hashing = Hashing.new(algorithm: proof.algorithm, encoding: proof.encoding, security: proof.security)
    end
  end
end
