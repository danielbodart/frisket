# What graphql-ruby makes of each document on stdin (a JSON array): its
# operations and their root fields, or null if it refuses the document.
require 'graphql'
require 'json'

N = GraphQL::Language::Nodes
out = JSON.parse($stdin.read).map do |doc|
  d = GraphQL.parse(doc)
  raise 'not executable' unless d.definitions.all? { |x| x.is_a?(N::FragmentDefinition) || x.is_a?(N::OperationDefinition) }
  frags = d.definitions.grep(N::FragmentDefinition).to_h { |f| [f.name, f] }
  root = lambda do |sels, seen|
    sels.flat_map do |s|
      case s
      when N::Field then [s.name]
      when N::InlineFragment then root.(s.selections, seen)
      else
        f = frags[s.name] or raise 'no fragment'
        raise 'cycle' if seen.include?(s.name)
        root.(f.selections, seen + [s.name])
      end
    end
  end
  ops = d.definitions.grep(N::OperationDefinition).map do |o|
    { 'Type' => o.operation_type || 'query', 'Name' => o.name || '', 'Fields' => root.(o.selections, []) }
  end
  ops.empty? ? nil : ops
rescue StandardError, SystemStackError
  nil
end
puts JSON.generate(out)
