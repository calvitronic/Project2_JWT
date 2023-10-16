require 'json'
require 'jwt'
require 'pp'

def main(context:, event:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  if event['path'] != '/' and event['path'] != '/token'
    return response(status: 404)
  elsif event['httpMethod'] == "GET"
    if event['path'].end_with?('/token')
      return response(status: 405)
    elsif !event['headers'] or !event['headers']['Authorization'] or !event['headers']['Authorization'].match?(/Bearer [\w-]+\.[\w-]+\.[\w-]+/)
      return response(status: 403)
    end
    begin
      token = event['headers']['Authorization'][7..-1]
      payload = JWT.decode(token, ENV['JWT_SECRET'], true, { :algorithm => 'HS256' })[0]
      return response(body: payload['data'], status: 200)
    rescue JWT::ImmatureSignature, JWT::ExpiredSignature
      return response(status: 401)
    rescue JWT::DecodeError
      return response(status: 403)
    end
  elsif event['httpMethod'] == "POST"
    if event['path'].end_with?('/')
      return response(status: 405)
    elsif event['headers']['Content-Type'] 
      if event['headers']['Content-Type'] != 'application/json'
        return response(status: 415)
      end
    end
    begin
      if !event['body']
        return response(status: 422)
      end
      request_body = JSON.parse(event['body'])
      payload = {
        data: request_body,
        exp: Time.now.to_i + 5,
        nbf: Time.now.to_i + 2
      }
      token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')
      return response(body: { "token" => token }, status: 201)
    rescue JSON::ParserError
      return response(status: 422)
    end
  else
    return response(status: 405)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = "NOTASECRET"

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 1 },
    exp: Time.now.to_i + 10,
    nbf: Time.now.to_i
  }
  token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end