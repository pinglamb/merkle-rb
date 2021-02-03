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

  describe 'properties' do
    it 'works for empty tree' do
      tree = Merkle::Tree.new
      expect(tree.length).to eq(0)
      expect(tree.size).to eq(0)
      expect(tree.height).to eq(0)
    end

    it 'works for tree with three leaves' do
      tree = Merkle::Tree.new('first', 'second', 'third')
      expect(tree.length).to eq(3)
      expect(tree.size).to eq(5)
      expect(tree.height).to eq(2)
    end
  end

  describe '#update' do
    it 'raises if both record and digest are provided' do
      tree = Merkle::Tree.new
      expect {
        tree.update(record: 'some record', digest: '540ef8fc9eefa3ec0fbe55bc5d10dbea03d5bac5591b3d7db3af79ec24b3f74c')
      }.to raise_error(Merkle::LeafConstructionError)
    end
  end

  describe '#clear' do
    it 'works' do
      tree = Merkle::Tree.new('a', 'b', 'c')
      tree.clear
      expect(tree.leaves).to be_empty
      expect(tree.nodes).to be_empty
      expect { tree.root }.to raise_error(Merkle::EmptyTreeException)
    end
  end
end
