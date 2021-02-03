# frozen_string_literal: true

require_relative 'merkle/version'
require_relative 'merkle/encoder'
require_relative 'merkle/hashing'
require_relative 'merkle/node'
require_relative 'merkle/tree'

module Merkle
  class UnsupportedHashType < StandardError; end
  class UnsupportedEncoding < StandardError; end
  class EmptyTreeException < StandardError; end
  class NoParentException < StandardError; end
  class NoChildException < StandardError; end
  class NoDescendantException < StandardError; end
  class LeafConstructionError < StandardError; end
end
