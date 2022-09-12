# BuuurstDev

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'buuurst_dev'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install buuurst_dev

## Usage
Write bellow code in config/application.rb ( or config/environments/{RAILS_ENV}.rb ).

    require "buuurst_dev/collector"

    config.middleware.insert_before(0, BuuurstDev::Collector)
## Configuration
Create initializer file at config/initializer/buuurst_dev.rb and write bellow code.

    BuuurstDev.configure do |config|
        config.enable = true
        config.project_id = 1
        config.user_key = 'user'
        config.custom_header = %w[Content-Type]
        config.ignore_paths = %w[/health]
    end

- enable
    - used for switching enabled/disabled of this gem
- project_id
    - used for identifying loadtest target app
- user_key
    - used for finding parameter identifying request user
- cunstom_header (optional)
    - used for logging header contents
- ignore_paths (optional)
    - ignore sending request log when request path is in ignore_paths 


## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/drecom/buuurst_dev.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
