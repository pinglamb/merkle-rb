# frozen_string_literal: true

module Merkle
  L_BRACKET_SHORT = "\u2514\u2500" # └─
  L_BRACKET_LONG = "\u2514\u2500\u2500" # └──
  T_BRACKET = "\u251C\u2500\u2500" # ├──
  VERTICAL_BAR = "\u2502" # │

  class NodeBase
    attr_reader :encoding

    def child
      @child || (raise NoChildException)
    end

    def child=(child)
      @child = child
    end

    def left
      @left || (raise NoParentException)
    end

    def right
      @right || (raise NoParentException)
    end

    def left_parent?
      begin
        self == child.left
      rescue NoChildException
        false
      end
    end

    def right_parent?
      begin
        self == child.right
      rescue NoChildException
        false
      end
    end

    def parent?
      !!@child
    end

    def descendant(degree)
      if degree == 0
        self
      else
        raise NoDescendantException unless parent?
        child.descendant(degree - 1)
      end
    end

    def pt(level: 0, indent: 3, ignore: [])
      output = ''
      if level == 0
        if !left_parent? && !right_parent?
          # root case
          output += " #{L_BRACKET_SHORT}"
        end
      else
        output += ' ' * (indent + 1)
      end
      (1...level).each do |l|
        if !ignore.include?(l)
          output += " #{VERTICAL_BAR}"
        else
          output += ' ' * 2
        end
        output += ' ' * indent
      end
      new_ignore = ignore.dup
      output += " #{T_BRACKET}" if left_parent?
      if right_parent?
        output += " #{L_BRACKET_LONG}"
        new_ignore << level
      end
      output += "#{digest}\n"
      unless is_a?(Leaf)
        output += left.pt(level: level + 1, indent: indent, ignore: new_ignore)
        output += right.pt(level: level + 1, indent: indent, ignore: new_ignore)
      end

      output
    end

    private

    def initialize(encoding)
      @encoding = encoding
    end
  end

  class Leaf < NodeBase
    attr_reader :digest

    private

    def initialize(hashing, encoding, record = nil, digest = nil)
      if digest.nil? && record
        super(encoding)
        @digest = hashing.digest(record)
      elsif record.nil? && digest
        super(encoding)
        @digest = digest
      else
        raise LeafConstructionError.new('Either record or digest should be provided')
      end
    end
  end

  class Node < NodeBase
    attr_reader :digest

    def right=(right)
      @right = right
    end

    def recalculate_hash(hashing)
      @digest = hashing.digest(@left.digest, @right.digest)
    end

    private

    def initialize(hashing, encoding, left, right)
      super(encoding)
      @digest = hashing.digest(left.digest, right.digest)
      @left = left
      @right = right
      left.child = self
      right.child = self
    end
  end
end
