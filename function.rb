# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

# Echo out API response to the server.
def response(body, status)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
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
      "response_body" => "Invalid HTTP Method",
      "response_status_code" => 405 
    } 
  end

  #Validate content type
  if(content_type != 'application/json')
    return {
      "response_body" => "Invalid Content Type",
      "response_status_code" => 415 
    } 
  end

  #Validate content string type
  if(!valid_json_format(request_body))
    return {
      "response_body" => "Invalid JSON String",
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
    "response_body" => { :token => (JWT.encode payload, ENV['JWT_SECRET'], 'HS256')},
    "response_status_code" => 201 
  }
end

# [GET] process the token and translate the token back
# to its original JSON string.
def get_token(endpoint, method, auth)
  #Validate endpoint with method!
  if(!valid_method(endpoint, method))
    return {
      "response_body" => "Invalid HTTP Method",
      "response_status_code" => 405 
    } 
  end

  #if auth header is empty, then no auth header was passed in!  
  auth = auth.split('Bearer ')
  auth = (auth[1] || "")

  if auth.empty?
    return {
      "response_body" => "No Authorization Header Is Provided.",
      "response_status_code" => 403 
    } 
  end

  #1. decode the HS256 string and parse it into Ruby hash
  # According to https://github.com/jwt/ruby-jwt
  # JWT will automatically verify expieration time!
  ENV['JWT_SECRET'] = 'CHENZHU'
  begin
    decoded = JWT.decode auth, ENV['JWT_SECRET'], true, { algorithm: 'HS256'}
  rescue JWT::ImmatureSignature
    return {
      "response_body" => "ImmatureSignature! ",
      "response_status_code" => 401 
    } 
  rescue JWT::ExpiredSignature
    return {
      "response_body" => "ExpiredSignature! ",
      "response_status_code" => 401 
    } 
  rescue JWT::DecodeError
    return {
      "response_body" => "Token Invalid! ",
      "response_status_code" => 403 
    } 
  end

  return {
    "response_body" => decoded["data"],
    "response_status_code" => 200 
  }

end

# This funciton parses out HTTP request and assign to 
# Corresponding Switch Case
def API_triggers(body)
  #process required header here!
  endpoint = body['path'].downcase
  method = (body['httpMethod'] || "").downcase
  request_body = (body['body'] || "")
  #Downgrade all hash keys! 
  headers = body['headers']
  headers = headers.transform_keys(&:downcase)
  content_type = (headers['content-type'] || "")#.downcase #Hummm case sensitive here. 
  auth = (headers['authorization'] || "")
  
  #puts(content_type.class)

  case endpoint
    when "/" #ONLY GET from here
      get_response = get_token(endpoint, method, auth)
      response(get_response['response_body'], get_response['response_status_code'])
    when "/token" #ONLY POST to token!
      post_response = post_token(endpoint, method, content_type, request_body)
      response(post_response['response_body'], post_response['response_status_code'])
    else 
      response(Array[], 404) #Source not found!
  end
end

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  
  #response(body: event, status: 200)
  #event = JSON.parse(event[:event])
  #puts event
  API_triggers(event)
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












