# frozen_string_literal: true

module Merkle
  class Proof
    attr_reader :algorithm, :encoding, :security, :commitment, :proof_index, :audit_path

    def valid?
      begin
        Validator.new(self).run
        true
      rescue InvalidMerkleProof
        false
      end
    end

    private

    def initialize(algorithm:, encoding:, security:, commitment:, proof_index:, proof_path:)
      @algorithm = algorithm
      @encoding = encoding
      @security = security
      @commitment = commitment
      @proof_index = proof_index
      @proof_path = proof_path
    end
  end
end
