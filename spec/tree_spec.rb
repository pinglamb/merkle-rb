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

  describe '#commitment' do
    it 'works for empty tree' do
      tree = Merkle::Tree.new
      expect(tree.commitment).to be_nil
    end

    it 'works for tree with three leaves' do
      tree = Merkle::Tree.new('first record', 'second record', 'third record')
      expect(tree.commitment).to eq(tree.root_hash)
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

  describe '#pp' do
    it 'works for empty tree' do
      tree = Merkle::Tree.new(algorithm: Digest::SHA512, encoding: 'utf-16', security: false)
      expect(tree.pp).to eq <<~STR
        hash-type : Digest::SHA512
        encoding  : UTF-16
        security  : DEACTIVATED

        root-hash : [None]

        length    : 0
        size      : 0
        height    : 0
        STR
    end

    it 'works for not empty tree' do
      tree = Merkle::Tree.new(*%w[first second third])
      expect(tree.pp).to eq <<~STR
        hash-type : Digest::SHA256
        encoding  : UTF-8
        security  : ACTIVATED

        root-hash : #{tree.root_hash}

        length    : 3
        size      : 5
        height    : 2
        STR
    end
  end

  describe '#pt' do
    it 'works for empty tree' do
      tree = Merkle::Tree.new
      expect(tree.pt).to eq <<~STR
      └─[None]
      STR
    end

    it 'works for one leaf tree' do
      tree = Merkle::Tree.new('first')
      expect(tree.pt).to eq <<~STR
      \s└─a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d
      STR
    end

    it 'works for three leaves tree' do
      tree = Merkle::Tree.new(*%w[first second third])
      expect(tree.pt).to eq <<~STR
      \s└─2427940ec5c9197add5f33423ba3971c3524f4b78f349ee45094b52d0d550fea
           ├──a84762b529735022ce1d7bdc3f24e94aba96ad8b3f6e4866bca76899da094df3
           │    ├──a1af030231ca2fd20ecf30c5294baf8f69321d09bb16ac53885ccd17a385280d
           │    └──a94dd4d3c2c6d2548ca4e560d72727bab5d795500191f5b85579130dd3b14603
           └──656d3e8f544238cdf6e32d640f51ba0914959b14edd7a52d0b8b99ab4c8ac6c6
      STR
    end
  end
end
