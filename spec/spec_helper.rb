# frozen_string_literal: true

require 'merkle'

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

module MerkleTest
  ALGORITHMS = [Digest::MD5, Digest::SHA256, Digest::SHA384, Digest::SHA512]
  ENCODINGS = %w[ascii utf-8 utf-16 utf-32]
end
