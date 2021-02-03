# frozen_string_literal: true

require 'digest'

RSpec.describe Merkle::Tree do
  def h(l, r = nil)
    Merkle::Hashing.new.digest(l, r)
  end

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
      expect(tree.root_hash).to eq(h('first record'))
    end

    it 'works with two leaves' do
      tree = Merkle::Tree.new('first record', 'second record')
      expect(tree.root_hash).to eq(h(h('first record'), h('second record')))
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
    context 'for restructuring' do
      MESSAGES = %w[ingi rum imus noc te et con su mi mur igni]

      it 'works with 0 leaves' do
        tree = Merkle::Tree.new
        expect { tree.root_hash }.to raise_error(Merkle::EmptyTreeException)
      end

      it 'works with 1 leaf' do
        t = Merkle::Tree.new(*MESSAGES[0..0])
        expect(t.root_hash).to eq(h(MESSAGES[0]))
      end

      it 'works with 2 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..1])
        expect(t.root_hash).to eq(h(h(MESSAGES[0]), h(MESSAGES[1])))
      end

      it 'works with 3 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..2])
        expect(t.root_hash).to eq(h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(MESSAGES[2])))
      end

      it 'works with 4 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..3])
        expect(t.root_hash).to eq(h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(h(MESSAGES[2]), h(MESSAGES[3]))))
      end

      it 'works with 5 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..4])
        expect(t.root_hash).to eq(
          h(h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(h(MESSAGES[2]), h(MESSAGES[3]))), h(MESSAGES[4]))
        )
      end

      it 'works with 6 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..5])
        expect(t.root_hash).to eq(
          h(h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(h(MESSAGES[2]), h(MESSAGES[3]))), h(h(MESSAGES[4]), h(MESSAGES[5])))
        )
      end

      it 'works with 7 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..6])
        expect(t.root_hash).to eq(
          h(
            h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(h(MESSAGES[2]), h(MESSAGES[3]))),
            h(h(h(MESSAGES[4]), h(MESSAGES[5])), h(MESSAGES[6]))
          )
        )
      end

      it 'works with 8 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..7])
        expect(t.root_hash).to eq(
          h(
            h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(h(MESSAGES[2]), h(MESSAGES[3]))),
            h(h(h(MESSAGES[4]), h(MESSAGES[5])), h(h(MESSAGES[6]), h(MESSAGES[7])))
          )
        )
      end

      it 'works with 9 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..8])
        expect(t.root_hash).to eq(
          h(
            h(
              h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(h(MESSAGES[2]), h(MESSAGES[3]))),
              h(h(h(MESSAGES[4]), h(MESSAGES[5])), h(h(MESSAGES[6]), h(MESSAGES[7])))
            ),
            h(MESSAGES[8])
          )
        )
      end

      it 'works with 10 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..9])
        expect(t.root_hash).to eq(
          h(
            h(
              h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(h(MESSAGES[2]), h(MESSAGES[3]))),
              h(h(h(MESSAGES[4]), h(MESSAGES[5])), h(h(MESSAGES[6]), h(MESSAGES[7])))
            ),
            h(h(MESSAGES[8]), h(MESSAGES[9]))
          )
        )
      end

      it 'works with 11 leaves' do
        t = Merkle::Tree.new(*MESSAGES[0..10])
        expect(t.root_hash).to eq(
          h(
            h(
              h(h(h(MESSAGES[0]), h(MESSAGES[1])), h(h(MESSAGES[2]), h(MESSAGES[3]))),
              h(h(h(MESSAGES[4]), h(MESSAGES[5])), h(h(MESSAGES[6]), h(MESSAGES[7])))
            ),
            h(h(h(MESSAGES[8]), h(MESSAGES[9])), h(MESSAGES[10]))
          )
        )
      end
    end

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
