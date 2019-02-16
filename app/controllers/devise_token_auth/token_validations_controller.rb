# frozen_string_literal: true

module DeviseTokenAuth
  class TokenValidationsController < DeviseTokenAuth::ApplicationController
    skip_before_action :assert_is_devise_resource!, only: [:validate_token]
    before_action :set_user_by_token, only: [:validate_token]
    before_action :set_user_by_refresh_token, only: [:refresh_token]

    def validate_token
      # @resource will have been set by set_user_by_token concern
      if @resource
        yield @resource if block_given?
        render_validate_token_success
      else
        render_validate_token_error
      end
    end

    def refresh_token
      if @resource
        @client_id, @token, @refresh_token = @resource.create_token(client_id: @client_id)

        @resource.tokens[@client_id] = {
          token: BCrypt::Password.create(@token),
          refresh_token: BCrypt::Password.create(@refresh_token),
          expiry: (Time.now + DeviseTokenAuth.token_lifespan).to_i
        }

        @resource.save

        render_validate_token_success
      else
        render_validate_token_error
      end
    end

    protected

    def render_validate_token_success
      render json: {
        success: true,
        data: resource_data(resource_json: @resource.token_validation_response)
      }
    end

    def render_validate_token_error
      render_error(401, I18n.t('devise_token_auth.token_validations.invalid'))
    end
  end
end
