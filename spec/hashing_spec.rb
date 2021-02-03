# frozen_string_literal: true

MESSAGE = 'oculusnonviditnecaurisaudivit'

RSpec.describe Merkle::Hashing do
  it 'digests single string' do
    hashing = Merkle::Hashing.new
    expect(hashing.digest(MESSAGE)).to eq('667573952e62c6e89303a1ba5a91372933a24324c0d8bb702f7d7d54c4c36b2a')
  end
end
