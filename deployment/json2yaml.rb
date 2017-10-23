#!/usr/bin/env ruby
#
require 'json'
require 'yaml'

input_filename = ARGV[0]
output_filename = input_filename.sub(/(json)$/, 'yaml')

input_file = File.open(input_filename, 'r')
input_json = input_file.read
input_file.close

output_yaml = YAML.dump(JSON::load(input_json))

output_file = File.open(output_filename, 'w+')
output_file.write(output_yaml)
output_file.close
