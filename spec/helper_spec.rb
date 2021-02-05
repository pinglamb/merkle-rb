# frozen_string_literal: true

RSpec.describe Merkle::Helper do
  describe '.decompose' do
    it 'works for 0' do
      expect(Merkle::Helper.decompose(0)).to eq([])
    end

    it 'works for -1' do
      expect(Merkle::Helper.decompose(-1)).to eq([])
    end

    it 'works for 45' do
      expect(Merkle::Helper.decompose(45)).to eq([5, 3, 2, 0])
    end
  end
end
