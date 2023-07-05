# frozen_string_literal: true

require 'uri'
require 'net/http'
require 'active_support/all'
require 'action_dispatch/http/headers'

require 'gem_config'

module BuuurstDev # rubocop:disable Style/Documentation
  include GemConfig::Base

  with_configuration do
    has :enable, default: false
    has :project_id, default: nil
    has :service_key, default: nil
    has :put_log_url, default: 'https://lambda-public.buuurst.dev/put-request-log'
    has :custom_header, default: []
    has :ignore_paths, default: []
  end

  # send request content and status code for auto loadtest
  class Collector
    def initialize(app)
      @app = app
      @enable = BuuurstDev.configuration.enable
      @project_id = BuuurstDev.configuration.project_id
      @service_key = BuuurstDev.configuration.service_key
      @put_log_url = BuuurstDev.configuration.put_log_url
      @custom_header = BuuurstDev.configuration.custom_header
      @ignore_paths = BuuurstDev.configuration.ignore_paths
    end

    def call(env)
      dup._call(env)
    end

    def _call(env)
      get_request_path(env) if @enable
      get_request_log(env) if @enable && enable_path?
      status, headers, body = @app.call(env)
      if @enable && enable_path?
        get_response_log(status, headers, body)
        send_log
      end
      [status, headers, body]
    end

    def send_log
      url = URI.parse(@put_log_url)
      req_header = { 'Content-Type': 'application/json' }
      param = create_param_json

      http = Net::HTTP.new(url.host, url.port)
      http.use_ssl = true
      http.post(url.path, param, req_header)
    end

    # rubocop:disable Metrics/MethodLength
    def create_param_json
      {
        project_id: @project_id,
        requested_at: @time_stamp,
        service_key: @service_key,
        method: @method,
        path: @path,
        query: @query,
        cookie: @cookie,
        request_id: @request_id,
        status: @status,
        header: @request_headers, # TODO: change key name to request_headers
        body: @request_body, # TODO: change key name to request_body
        response_headers: @response_headers,
        response_body: @response_body
      }.to_json
    end
    # rubocop:enable Metrics/MethodLength

    def get_request_path(env)
      @path = env['PATH_INFO']
    end

    def get_request_log(env)
      @time_stamp = Time.current.to_i
      @method = env['REQUEST_METHOD']
      @query = Rack::Utils.parse_nested_query(env['QUERY_STRING'])
      @cookie = Rack::Utils.parse_cookies(env)
      get_request_header(env)
      @request_id = env['HTTP_X_REQUEST_ID']
      get_request_body(env)
    end

    def get_response_log(status, headers, body)
      @request_id ||= headers['X-Request-Id']
      @status = status
      @response_headers = headers # TODO: convert header?
      get_response_body(body)
    end

    private

    def enable_path?
      return false if @path.nil?
      return @enable_path unless @enable_path.nil?

      if @ignore_paths.size <= 0
        @enable_path = true
        return @enable_path
      end

      @enable_path = !@ignore_paths.include?(@path)
    end

    def get_request_header(env)
      @http_header_hash = {}
      @cgi_header_hash = {}
      create_header_mapping_hash
      @request_headers = env.select { |k, _v| k.start_with?('HTTP_') || @cgi_header_hash.keys.include?(k) }
      header_convert_hash = @http_header_hash.merge(@cgi_header_hash)
      @request_headers.transform_keys! { |k| header_convert_hash.include?(k) ? header_convert_hash[k] : k }
    end

    def create_header_mapping_hash
      @custom_header.each do |elem|
        next unless ActionDispatch::Http::Headers::HTTP_HEADER.match?(elem)

        name = elem.upcase
        name.tr!('-', '_')
        if ActionDispatch::Http::Headers::CGI_VARIABLES.include?(name)
          @cgi_header_hash[name] = elem
        else
          @http_header_hash[name.prepend('HTTP_')] = elem
        end
      end
    end

    def get_request_body(env)
      input = env['rack.input']
      @request_body = input.gets
      input.rewind
    end

    def get_response_body(body)
      @response_body = parse_json_string(body.join)
    end

    def parse_json_string(str)
      JSON.parse(str)
    rescue JSON::ParserError
      str
    end
  end
end
