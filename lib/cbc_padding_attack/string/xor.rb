class String
  def ^(other)
    self.bytes.zip(other.bytes).
      map {|pair| pair.inject(:^) }.
      map(&:chr).
      join
  end
end
