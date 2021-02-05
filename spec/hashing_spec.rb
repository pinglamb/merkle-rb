# frozen_string_literal: true

require 'digest'

RSpec.describe Merkle::Hashing do
  MESSAGE = 'oculusnonviditnecaurisaudivit'

  ALGORITHMS = [Digest::MD5, Digest::SHA256, Digest::SHA384, Digest::SHA512]
  ENCODINGS = %w[ascii utf-8 utf-16 utf-32]

  [true, false].each do |security|
    ALGORITHMS.each do |algorithm|
      ENCODINGS.each do |encoding|
        hashing = Merkle::Hashing.new(algorithm: algorithm, encoding: encoding, security: security)
        describe '#digest' do
          it "digests single string [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expect(hashing.digest(MESSAGE)).to eq(algorithm.hexdigest("\x00#{MESSAGE}".force_encoding(encoding)))
            else
              expect(hashing.digest(MESSAGE)).to eq(algorithm.hexdigest("#{MESSAGE}".force_encoding(encoding)))
            end
          end

          it "digests double string [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expect(hashing.digest(MESSAGE, MESSAGE)).to eq(
                algorithm.hexdigest("\x01#{MESSAGE}\x01#{MESSAGE}".force_encoding(encoding))
              )
            else
              expect(hashing.digest(MESSAGE, MESSAGE)).to eq(
                algorithm.hexdigest("#{MESSAGE}#{MESSAGE}".force_encoding(encoding))
              )
            end
          end
        end

        describe '#multi_digest' do
          it "raises EmptyPathException when empty [#{algorithm}, #{encoding}, #{security}]" do
            expect { hashing.multi_digest([], 'anything') }.to raise_error(Merkle::EmptyPathException)
          end

          it "digests one element [#{algorithm}, #{encoding}, #{security}]" do
            expect(hashing.multi_digest([[+1, hashing.digest(MESSAGE)]], 0)).to eq(hashing.digest(MESSAGE))
          end

          it "digests two elements [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE]], 0)).to eq(hashing.digest(MESSAGE, MESSAGE))
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE]], 1)).to eq(hashing.digest(MESSAGE, MESSAGE))
            else
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE]], 0)).to eq(
                hashing.digest("#{MESSAGE}#{MESSAGE}")
              )
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE]], 1)).to eq(
                hashing.digest("#{MESSAGE}#{MESSAGE}")
              )
            end
          end
        end
      end
    end
  end
end
