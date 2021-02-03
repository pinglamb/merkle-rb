# frozen_string_literal: true

RSpec.describe Merkle::Tree do
  describe '#empty?' do
    it 'it true if it is empty' do
      expect(Merkle::Tree.new).to be_empty
    end

    it 'is false if it is not empty' do
      expect(Merkle::Tree.new('some record')).not_to be_empty
    end
  end

  describe '#root' do
    it 'raises when empty' do
      expect { Merkle::Tree.new.root }.to raise_error(Merkle::EmptyTreeException)
    end
  end

  describe '#rootHash' do
    it 'works with one leaf' do
      tree = Merkle::Tree.new('first record')
      expect(tree.root_hash).to eq(tree.hashing.digest('first record'))
    end

    it 'works with two leaves' do
      tree = Merkle::Tree.new('first record', 'second record')
      expect(tree.root_hash).to eq(
        tree.hashing.digest(tree.hashing.digest('first record'), tree.hashing.digest('second record'))
      )
    end

    it 'raises when empty' do
      expect { Merkle::Tree.new.root_hash }.to raise_error(Merkle::EmptyTreeException)
    end
  end
end
