# frozen_string_literal: true

RSpec.describe Merkle::Proof do
  MAX_LENGTH = 4

  ALGORITHMS = [Digest::MD5, Digest::SHA256, Digest::SHA384, Digest::SHA512]
  ENCODINGS = %w[ascii utf-8 utf-16 utf-32]

  describe '#valid?' do
    [true, false].each do |security|
      ALGORITHMS.each do |algorithm|
        ENCODINGS.each do |encoding|
          (1..MAX_LENGTH).each do |length|
            tree =
              Merkle::Tree.new(
                *(0...length).collect { |i| "#{i}-th record" },
                algorithm: algorithm,
                encoding: encoding,
                security: security
              )

            context 'for audit proof' do
              (0...tree.length).each do |index|
                it "works for #{index}-th record in tree-#{tree.length} [#{algorithm}, #{encoding}, #{security}]" do
                  proof = tree.audit_proof(tree.hashing.digest("#{index}-th record"))
                  expect(proof).to be_valid(target: tree.root_hash)
                end
              end

              it "is invalid for invalid proof for tree-#{tree.length} [#{algorithm}, #{encoding}, #{security}]" do
                proof = tree.audit_proof(tree.hashing.digest('anything that has not been recorded'))
                expect(proof).not_to be_valid(target: tree.root_hash)
              end
            end

            context 'for consistency proof' do
              (1..tree.length).each do |sublength|
                it "works for subtree-#{sublength} in tree-#{tree.length} [#{algorithm}, #{encoding}, #{security}]" do
                  subtree =
                    Merkle::Tree.new(
                      *(0...sublength).collect { |i| "#{i}-th record" },
                      algorithm: algorithm,
                      encoding: encoding,
                      security: security
                    )
                  proof = tree.consistency_proof(subtree.root_hash)
                  expect(proof).to be_valid(target: tree.root_hash)
                end

                it "is invalid for invalid proof for tree-#{tree.length} [#{algorithm}, #{encoding}, #{security}]" do
                  proof = tree.consistency_proof('anything except for the right hash')
                  expect(proof).not_to be_valid(target: tree.root_hash)
                end
              end
            end
          end
        end
      end
    end
  end
end
