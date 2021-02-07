# frozen_string_literal: true

RSpec.describe Merkle::Tree do
  describe '#include?' do
    [true, false].each do |security|
      MerkleTest::ALGORITHMS.each do |algorithm|
        MerkleTest::ENCODINGS.each do |encoding|
          tree = Merkle::Tree.new(*%w[a b c d e], algorithm: algorithm, encoding: encoding, security: security)
          subhash = tree.root_hash
          %w[f g h k].each { |record| tree.update(record: record) }

          it "works for valid subtree [#{algorithm}, #{encoding}, #{security}]" do
            expect(tree).to include(subhash)
          end
        end
      end
    end

    it 'does not include anything for empty tree' do
      expect(Merkle::Tree.new).not_to include('something')
    end
  end
end
