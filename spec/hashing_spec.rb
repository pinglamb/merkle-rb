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
          it "digests 1 string [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expect(hashing.digest(MESSAGE)).to eq(algorithm.hexdigest("\x00#{MESSAGE}".force_encoding(encoding)))
            else
              expect(hashing.digest(MESSAGE)).to eq(algorithm.hexdigest("#{MESSAGE}".force_encoding(encoding)))
            end
          end

          it "digests 2 strings [#{algorithm}, #{encoding}, #{security}]" do
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
          define_method(:h, &hashing.method(:digest))

          it "raises EmptyPathException when empty [#{algorithm}, #{encoding}, #{security}]" do
            expect { hashing.multi_digest([], 'anything') }.to raise_error(Merkle::EmptyPathException)
          end

          it "digests 1 element [#{algorithm}, #{encoding}, #{security}]" do
            expect(hashing.multi_digest([[+1, hashing.digest(MESSAGE)]], 0)).to eq(h(MESSAGE))
          end

          it "digests 2 elements [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expected = h(MESSAGE, MESSAGE)
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE]], 0)).to eq(expected)
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE]], 1)).to eq(expected)
            else
              expected = h("#{MESSAGE}#{MESSAGE}")
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE]], 0)).to eq(expected)
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE]], 1)).to eq(expected)
            end
          end

          it "digests 3 elements case 1 [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expected = h(h(MESSAGE, MESSAGE), MESSAGE)
              expect(hashing.multi_digest([[+1, MESSAGE], [+1, MESSAGE], ['_anything_', MESSAGE]], 0)).to eq(expected)
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE], ['_anything_', MESSAGE]], 1)).to eq(expected)
            else
              expected = h(h("#{MESSAGE}#{MESSAGE}"), MESSAGE)
              expect(hashing.multi_digest([[+1, MESSAGE], [+1, MESSAGE], ['_anything_', MESSAGE]], 0)).to eq(expected)
              expect(hashing.multi_digest([[+1, MESSAGE], [-1, MESSAGE], ['_anything_', MESSAGE]], 1)).to eq(expected)
            end
          end

          it "digests 3 elements case 2 [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expected = h(MESSAGE, h(MESSAGE, MESSAGE))
              expect(hashing.multi_digest([['_anything_', MESSAGE], [-1, MESSAGE], [-1, MESSAGE]], 2)).to eq(expected)
              expect(hashing.multi_digest([['_anything_', MESSAGE], [+1, MESSAGE], [-1, MESSAGE]], 1)).to eq(expected)
            else
              expected = h(MESSAGE, h("#{MESSAGE}#{MESSAGE}"))
              expect(hashing.multi_digest([['_anything_', MESSAGE], [-1, MESSAGE], [-1, MESSAGE]], 2)).to eq(expected)
              expect(hashing.multi_digest([['_anything_', MESSAGE], [+1, MESSAGE], [-1, MESSAGE]], 1)).to eq(expected)
            end
          end

          it "digests 4 elements edge case 1 [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expected = h(h(h(MESSAGE, MESSAGE), MESSAGE), MESSAGE)
              expect(
                hashing.multi_digest([[+1, MESSAGE], [+1, MESSAGE], [+1, MESSAGE], ['_anything_', MESSAGE]], 0)
              ).to eq(expected)
            else
              expected = h(h(h("#{MESSAGE}#{MESSAGE}"), MESSAGE), MESSAGE)
              expect(
                hashing.multi_digest([[+1, MESSAGE], [+1, MESSAGE], [+1, MESSAGE], ['_anything_', MESSAGE]], 0)
              ).to eq(expected)
            end
          end

          it "digests 4 elements edge case 2 [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expected = h(MESSAGE, h(MESSAGE, h(MESSAGE, MESSAGE)))
              expect(
                hashing.multi_digest([['_anything_', MESSAGE], [-1, MESSAGE], [-1, MESSAGE], [-1, MESSAGE]], 3)
              ).to eq(expected)
            else
              expected = h(MESSAGE, h(MESSAGE, h("#{MESSAGE}#{MESSAGE}")))
              expect(
                hashing.multi_digest([['_anything_', MESSAGE], [-1, MESSAGE], [-1, MESSAGE], [-1, MESSAGE]], 3)
              ).to eq(expected)
            end
          end

          it "digests 4 elements [#{algorithm}, #{encoding}, #{security}]" do
            if security
              expected = h(h(MESSAGE, h(MESSAGE, MESSAGE)), MESSAGE)
              expect(hashing.multi_digest([[+1, MESSAGE], [+1, MESSAGE], [-1, MESSAGE], [-1, MESSAGE]], 1)).to eq(
                expected
              )
            else
              expected = h(h(MESSAGE, h("#{MESSAGE}#{MESSAGE}")), MESSAGE)
              expect(hashing.multi_digest([[+1, MESSAGE], [+1, MESSAGE], [-1, MESSAGE], [-1, MESSAGE]], 1)).to eq(
                expected
              )
            end
          end
        end
      end
    end
  end
end
