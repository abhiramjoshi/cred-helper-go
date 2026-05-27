build name="cred-helper-go" clientId="" prodUrl="" devUrl="":
  go build -ldflags "\
  -X 'github.com/abhiramjoshi/cred-helper-go/pkg/vars.CliCommand={{name}}' \
  -X 'github.com/abhiramjoshi/cred-helper-go/pkg/vars.ClientId={{clientId}}' \
  -X 'github.com/abhiramjoshi/cred-helper-go/pkg/vars.ProdBaseUrl={{prodUrl}}' \
  -X 'github.com/abhiramjoshi/cred-helper-go/pkg/vars.DevBaseUrl={{devUrl}}'" \
  -o bin/{{name}}
  
