# Rails Security Guide

## Overview
Disclaimer: This security guide isn't intended to be exhaustive 

Use this guide before each deployment, or, even better, use an automated process.

**Definitions**
- _Never_: Never means never
- _Don't_: Don't unless you have a really really good reason
- _Avoid_: Avoid unless you have a good reason

**Gems**
* [Brakeman](https://github.com/presidentbeef/brakeman) - A static analysis security vulnerability scanner for Ruby on Rails applications
* [Rack::Attack!!](https://github.com/kickstarter/rack-attack) - Rack middleware for blocking & throttling
* [SecureHeaders](https://github.com/github/secure_headers) - Security related headers all in one gem
* [Sanitize](https://github.com/rgrove/sanitize) - An allowlist-based HTML and CSS sanitizer
* [zxcvbn](https://github.com/bitzesty/devise_zxcvbn) - Devise plugin to reject weak passwords using zxcvbn
* [StrongPassword](https://github.com/bdmac/strong_password) - Entropy-based password strength checking for Ruby and Rails
* [Pundit](https://github.com/varvet/pundit) - Minimal authorization through OO design and pure Ruby classes

**TOC**
* [Injections](#injections)
* [Cross-site Scripting (XSS)](#cross-site-scripting)
* [Authentication and Sessions](#authentication-and-sessions)
* [Authorization](#authorization)
* [Cross-Site Request Forgery](#cross-site-request-forgery)
* [Insecure Direct Object Reference or Forceful Browsing](#insecure-direct-object-reference-or-forceful-browsing)
* [Redirects](#redirects)
* [Files](#files)
* [Cross-Origin Resource Sharing](#cross-origin-resource-sharing)
* [Data Leaking and Logging](#data-leaking-and-logging)
* [Misc](#misc)

## Injections
- [ ] Parameterize or serialize user input (including URL query params) before using it
- [ ] Don't pass strings as parameters to Active Records methods. Use arrays or hashes instead
- [ ] Never use user input directly when using the `delete_all` method
- [ ] Never use user input in system commands
- [ ] Avoid system commands 
- [ ] Sanitize ALL hand-written SQL [ActiveRecord Sanitization](https://api.rubyonrails.org/classes/ActiveRecord/Sanitization/ClassMethods.html)

```
# bad 
User.find_by("id = '#{params[:user_id]'")

User.delete_all("id = #{params[:user_id]}")

User.where(admin: false).group(params[:group])
User.where("name = '#{params[:name]'")

# good
User.find(id)
User.find_by(id: params[:id])
User.find_by_id(params[:id].to_i) # better

User.where({ name: params[:name] })
User.where(admin: false).group(:name)
User.where("name LIKE ?", "#{params[:search]}%")
User.where("name LIKE ?", User.sanitize_sql_like(params[:search]) + "%")
```

## Cross-site Scripting
By default, when string data is shown in views, it is escaped prior to being sent back to the browser.

- [ ] Never disable `ActiveSupport#escape_html_entities_in_json`
- [ ] Don't use `raw`, `html_safe`, `content_tag`, or `<%==`
- [ ] Prefer Markdown over HTML
- [ ] Validate and sanitize user input for Urls and Html (including classes or attributes)
- [ ] Never create templates in code (use ERB, Slim, Haml, etc)
- [ ] Never use `render inline` or `render text`
- [ ] Never use unquoted variables in HTML attribute
- [ ] Don't use template variables in script blocks 
- [ ] Implement [Content Security Policy](https://guides.rubyonrails.org/v7.0/security.html#content-security-policy-header
) or use SecureHeaders gem if below Rails v5.2 

```
# bad 
config.action_view.escape_html_entities_in_json = false
<%= raw @user.bio %>
<%= @user.bio.html_safe %>
<%= link_to "Personal Website", @user.personal_website %>

<div class=<%= params[:css_class] %></div>
<script>var name = <%= @user.name %>;</script>
render inline: "<div>#{@user.name}</div>"

# good
sanitize(@user.bio, tags: %w(b br em i p strong), attributes: %w())
strip_tags("Strip <i>these</i> tags!") # => Strip these tags!
strip_links('<a href="http://www.rubyonrails.org">Ruby on Rails</a>') # => Ruby on Rails

validates :instagram, url: true, allow_blank: true # link_to("Instagram", @user.instagram)
validates :color, hex_color: true # HexColorValidator # <div style="background-color: <% user.color %>">
```

## Authentication and Sessions
- [ ] Use a database based session store
- [ ] Never put sensitive information in the session
- [ ] Set an expiration for the session (Limit: 30 minutes)
- [ ] Limit "Remember Me" functionality to 2 weeks
- [ ] The same timeline can be used for access & refresh tokens
- [ ] Set all cookies and session store as httponly and secure
- [ ] Revalidate cookie values
- [ ] Never store "state" in the session or a cookie
- [ ] Enforce password complexity (min length, no words, etc)
- [ ] Consider captcha on publicly available forms 
- [ ] Consider captcha after several failed login attempts 
- [ ] Always confirm user emails 
- [ ] Require old password to change password (except for forgot password)
- [ ] Expire password reset tokens after 10 minutes
- [ ] Limit password reset emails within a specified timeframe 
- [ ] Consider using two-factor authentication (2FA) (required if storing sensitive data)
- [ ] Don't use "Security Questions"
- [ ] Use generic error messages for failed login attempts (Email or password is invalid)
- [ ] add `before_action :authenticate_user!` to ApplicationController and `skip_before_action :authenticate_user!` to publicly accessible controllers/actions.

```
# bad
Rails.application.config.session_store :my_custom_store, expire_after: 2.years
JWT.encode payload, nil, 'none'

# good
Rails.application.config.session_store :active_record_store, expire_after: 30.minutes, httponly: true, secure: true
cookies[:login] = {value: "user", httponly: true, secure: true}
JWT.encode({ data: 'data', exp: Time.now.to_i + 4 * 3600 }, hmac_secret, 'HS256')
config.force_ssl = true
```

## Authorization
- [ ] NEVER do authorization on the frontend
- [ ] Admin interface should be isolated from the user interface
- [ ] Use 2FA on the admin interface
- [ ] Don't use `accepts_nested_attributes_for` for permissions 
- [ ] Prefer policies over querying by association (current_user.posts)
- [ ] Always use policies if using multi-user accounts   

```
# bad
@posts = Post.where(user_id: params[:user_id])
@comment = Commend.find_by(id: params[:id])
accepts_nested_attributes_for :permission

# good
@posts = current_user.posts
@posts = policy_scope(Post)
@comment = current_user.comments.find_by(id: params[:id])
authorize @post
```

## Cross-Site Request Forgery
- [ ] If you use cookie-based authentication anywhere, use `protect_from_forgery`
- [ ] If you use token-based authentication, you don't need `protect_from_forgery`

```
# Newer versions of Rails use:
config.action_controller.default_protect_from_forgery

# Implementation 
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  rescue_from ActionController::InvalidAuthenticityToken do |exception|
    sign_out_user # destroy the user cookies
  end
  
  ...(rest of file)...
end
```

## Insecure Direct Object Reference or Forceful Browsing
This is basically guessing ids in the path: `https://example.com/user/10`

- [ ] Use UUIDs, [hashids](https://github.com/peterhellberg/hashids.rb), or a non-guessable id
- [ ] Avoid changing the default primary key (`id`)
- [ ] Policies can help mitigate this as well
- [ ] Don't let a user-supplied params to determine which view to render
- [ ] Don't show the numerical `id` in an API call when using a uuid, hashid, etc

```
Stripe Customer ID = cus_9s6XFG2Qq6Fe7v

# don't do this
def show
  render params[:user_supplied_view]
end
```

## Redirects
- [ ] Avoid passing any user-supplied params into `redirect_to`
- [ ] If you must use user-supplied URLs for redirect_to... sanitize or use an allowlist
- [ ] Validate with regex using \A and \z as anchors, _not_ ^ and $
- [ ] If your needs are complex, use [Shopify's redirect_safely gem](https://github.com/shopify/redirect_safely)

```
# bad
redirect_to params[:url]
redirect_to URI.parse(params[:url]).path
redirect_to URI.parse("#{params[:url]}").host
redirect_to "https://yourwebsite.com/" + params[:url]

# ok, but not good
redirect_to "https://instagram.com/" + params[:ig_username]

# good
redirect_to user.redirect_url # sanitize beforehand 
redirect_to AllowList.include?(params[:url]) ? params[:url] : '/'
```

## Files
- [ ] Avoid user-generated filenames (e.g ../../passwd), assign random names if possible
- [ ] Only allow alphanumeric, underscores, hyphens, and periods
- [ ] Don't process images or videos on your server 
- [ ] Always (re)validate on the backend (file size, media type, name, etc.)
- [ ] Process media files asynchronously
- [ ] Use 3rd party scanners if necessary
- [ ] Prefer cloud storage services such as Amazon S3 to directly handle file uploads and storage

## Cross-Origin Resource Sharing 
- [ ] Use [rack-cors gem](https://github.com/cyu/rack-cors)
- [ ] Unless your API is open to anyone, don't set wildcard as an origin. 

```
# bad
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins'*'
    resource '*', headers: :any, methods: :any
  end
end

# good
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins'  http://example.com:80' # regular expressions can be used here
    resource '*', headers: :any, methods: [:get, :post]
  end
end

Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins' http://example.com:80'
    resource '/orders',
      :headers => :any,
      :methods => [:post]
    resource'/users',
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head]
  end
end

Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    if Rails.env.development?
      origins 'localhost:3000', 'localhost:3001', 'https://yourwebsite.com'
    else
      origins' https://yourwebsite.com'
    end

    resource '*', 
      headers: :any, 
       methods: [:get, :post, :put, :patch, :delete, :options, :head]
  end
end
```

## Data Leaking and Logging
- [ ] NEVER commit credentials, passwords, or keys 
- [ ] Use `config.filter_parameters` for sensitive data (passwords, tokens, etc)
- [ ] Use `config.filter_redirect` for sensitive location you redirect to
- [ ] Don't use 403 Forbidden for authorized errors (it implies the resource exists)
- [ ] Don't include implementation details in view comments 
- [ ] Don't write your own encryption

## Misc
- [ ] [Encrypt](https://guides.rubyonrails.org/active_record_encryption.html) sensitive data at the application layer 
- [ ] Don't do this in routes `match ':controller(/:action(/:id(.:format)))"`
- [ ] Only use `https` gem sources
- [ ] Use blocks for more than one gem source 
- [ ] Never set `config.consider_all_requests_local = true` in production
- [ ] Separate gems by environment
- [ ] Don't use development-related gems (better_errors) in public-facing environments
- [ ] Don't make non-action controller methods public  
- [ ] Use `JSON.parse` over `JSON.load`
- [ ] Keep dependencies up-to-date and watch for vulnerabilities 
- [ ] Don't store credit card information
- [ ] Avoid user-supplied data in emails to other users 
- [ ] Avoid user-created email templates (heavily sanitize or markdown if necessary)
- [ ] Use `_html` for I18n keys with HTML tags 


**Additional Resources**
* [Official Rails Security Guide](https://guides.rubyonrails.org/security.html)
* [OWASP: Types of XSS](https://owasp.org/www-community/Types_of_Cross-Site_Scripting)
* [OWAS: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [Rails SQL Injections](https://rails-sqli.org/)
