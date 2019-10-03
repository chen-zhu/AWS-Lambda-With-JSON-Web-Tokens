# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  #response(body: event, status: 200)
  API_triggers(body: event)
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

# This funciton parses out HTTP request and assign to 
# Corresponding Switch Case
def API_triggers(body: nil)
  endpoint = body['path'].downcase
  method = (body['httpMethod'] || "").downcase
  request_body = (body['body'] || "")
  content_type = (body['headers']['Content-Type'] || "").downcase
  auth = (body['headers']['Authorization'] || "")

  case endpoint
  when "/" #ONLY GET from here

  when "/token" #ONLY POST to token!
    post_response = post_token(endpoint, method, content_type, request_body)
    response(post_response['response_body'], post_response['response_status_code'])
  else 
    response(Array[], 404) #Source not found!
  end
end

# Verify if the requested http method is allowed to 
# perform on the given endpoint. 
def valid_method(endpoint, http_method)
  allowed_list = {
    '/' => ['get'], 
    '/token' => ['post']
  }
  return allowed_list[endpoint].include? http_method
end 

# Verify if the given string is in valid Json format or not.
def valid_json_format(json_string)
  begin
    JSON.parse(json_string)
    return true
  rescue JSON::ParserError => json_parse_error
    return false
  end
end


# [POST] process data content for the endpoint /token
# Data content must contain valid json string
# then output {token => HS256<{data, exp nbf}>} content
def post_token(endpoint, method, content_type, request_body) 
  #Validate endpoint with method!
  if(!valid_method(endpoint, method))
    return {
      "response_body" => "Invalid HTTP Method"
      "response_status_code" => 405 
    } 
  end

  #Validate content type
  if(content_type != 'application/json')
    return {
      "response_body" => "Invalid Content Type"
      "response_status_code" => 415 
    } 
  end

  #Validate content string type
  if(!valid_json_format(request_body))
    return {
      "response_body" => "Invalid JSON String"
      "response_status_code" => 422 
    } 
  end


  ENV['JWT_SECRET'] = 'CHENZHU'
  payload = {
    :data => request_body,
    :exp => Time.now.to_i + 5, #5s later
    :nbf => Time.now.to_i + 2  #2s later
  }

  return {
    "response_body" => { :token => JWT.encode payload, ENV['JWT_SECRET'], 'HS256'}
    "response_status_code" => 201 
  }
end


def get_token()
  



end


#TODO: remove the following lines after done with testing!. 
#if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  #ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  #PP.pp main(context: {}, event: {
  #             'body' => '{"name": "bboe"}',
  #             'headers' => { 'Content-Type' => 'application/json' },
  #             'httpMethod' => 'POST',
  #             'path' => '/token'
  #           })

  # Generate a token
  #payload = {
  #  data: { user_id: 128 },
  #  exp: Time.now.to_i + 1,
  #  nbf: Time.now.to_i
  #}
  #token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  #PP.pp main(context: {}, event: {
  #             'headers' => { 'Authorization' => "Bearer #{token}",
  #                            'Content-Type' => 'application/json' },
  #             'httpMethod' => 'GET',
  #             'path' => '/'
  #          })
#end












