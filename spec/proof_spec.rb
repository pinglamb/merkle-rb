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
              tree.length.times do |index|
                it "works for valid proof for #{index}-th record [#{algorithm}, #{encoding}, #{security}]" do
                  proof = tree.audit_proof(tree.hashing.digest("#{index}-th record"))
                  expect(proof).to be_valid(target: tree.root_hash)
                end
              end

              it 'works for invalid proof' do
                proof = tree.audit_proof(tree.hashing.digest('anything that has not been recorded'))
                expect(proof).not_to be_valid(target: tree.root_hash)
              end
            end
          end
        end
      end
    end
  end
end
