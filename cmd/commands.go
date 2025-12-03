package cmd

import (
	"github.com/abhiramjoshi/cred-helper-go/internal"
	"github.com/spf13/cobra"
)

var login = &cobra.Command{
	Use: "login",
	Short: "Initiate auth flow to generate JWT for authorization",
	RunE: func(cmd *cobra.Command, args []string) error {
		openid, err := cmd.Flags().GetBool("openid")
		if err != nil {return err}
		err = internal.Login(cmd.Context(), openid)
		if err != nil {
			return err
		}
		return nil
	},
}

var refresh = &cobra.Command{
	Use: "refresh",
	Short: "Initiate refresh flow, if refresh token is not available will default to login flow",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := internal.Refresh(cmd.Context())
		if err != nil {
			return err
		}
		return nil
	},
}

func init(){
	login.Flags().BoolP("openid", "o", true, "Retrieve openid token")
	refresh.Flags().BoolP("openid", "o", true, "Retrieve openid token")
}
