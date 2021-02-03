# frozen_string_literal: true

require 'digest'
require 'set'

module Merkle
  class Tree
    attr_reader :hashing, :leaves, :nodes

    def empty?
      @nodes.empty?
    end

    def root
      raise EmptyTreeException if empty?
      @root
    end

    def root_hash
      raise EmptyTreeException if empty?
      @root.digest
    end

    def length
      @leaves.length
    end

    def size
      @nodes.length
    end

    def height
      # Since the tree is binary *balanced*, its height coincides
      # with the length of its leftmost branch
      len = @leaves.length
      len == 0 ? 0 : Math.log2(len).ceil
    end

    def update(record: nil, digest: nil)
      new_leaf = Leaf.new(@hashing, @encoding, record, digest)
      if empty?
        @leaves << new_leaf
        @nodes << new_leaf
        @root = new_leaf
      else
        # ~ Height and root of the *full* binary subtree with maximum
        # ~ possible length containing the rightmost leaf
        last_leaf = @leaves[-1]

        # TODO Find the last_subroot
        last_subroot = last_leaf

        @leaves << new_leaf
        @nodes << new_leaf

        if last_subroot.parent?
          old_child = last_subroot.child

          # Create bifurcation node
          new_node = Node.new(@hashing, @encoding, last_subroot, new_leaf)
          @nodes << new_node

          # Interject bifurcation node
          old_child.right = new_node
          new_node.child = old_child

          # Recalculate hashes only at the rightmost branch of the tree
          current_node = old_child
          loop do
            current_node.recalculate_hash(@hashing)
            break unless current_node.parent?
            current_node = current_node.child
          end
        else
          new_node = Node.new(@hashing, @encoding, last_subroot, new_leaf)
          @nodes << new_node
          @root = new_node
        end
      end
    end

    def clear
      @leaves = []
      @nodes = Set[]
      @root = nil
    end

    private

    def initialize(*records, algorithm: Digest::SHA256, encoding: 'utf-8', security: true)
      # Hashing configuration
      @hashing = Hashing.new(algorithm: algorithm, encoding: encoding, security: security)
      @encoding = encoding

      # Tree generation
      @leaves = []
      @nodes = Set[]
      records.each { |record| update(record: record) }
    end
  end
end
