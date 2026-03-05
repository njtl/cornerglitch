app = Proc.new do |env|
  path = env['PATH_INFO']
  method = env['REQUEST_METHOD']

  case [method, path]
  when ['GET', '/']
    [200, {'content-type' => 'text/html'}, ['<html><body><h1>Puma Target</h1><p>Default config, no hardening.</p></body></html>']]
  when ['GET', '/health']
    [200, {'content-type' => 'text/plain'}, ['ok']]
  when ['POST', '/login']
    body = env['rack.input'].read
    [200, {'content-type' => 'text/html'}, ["<html><body><h1>Login received</h1><pre>#{body}</pre></body></html>"]]
  else
    [404, {'content-type' => 'text/plain'}, ['Not Found']]
  end
end

run app
