"""
Forms module with WTForms validators for secure input handling
"""
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import (
    DataRequired, 
    Email, 
    Length, 
    Regexp, 
    EqualTo,
    ValidationError
)
import re


class UserForm(FlaskForm):
    """Form for creating and updating users with comprehensive validation"""
    
    first_name = StringField(
        'First Name',
        validators=[
            DataRequired(message='First name is required'),
            Length(min=2, max=50, message='First name must be between 2 and 50 characters'),
            Regexp(
                r'^[A-Za-z\s\-\']+$',
                message='First name can only contain letters, spaces, hyphens, and apostrophes'
            )
        ],
        render_kw={'placeholder': 'Enter first name', 'class': 'form-control'}
    )
    
    last_name = StringField(
        'Last Name',
        validators=[
            DataRequired(message='Last name is required'),
            Length(min=2, max=50, message='Last name must be between 2 and 50 characters'),
            Regexp(
                r'^[A-Za-z\s\-\']+$',
                message='Last name can only contain letters, spaces, hyphens, and apostrophes'
            )
        ],
        render_kw={'placeholder': 'Enter last name', 'class': 'form-control'}
    )
    
    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Invalid email address'),
            Length(max=120, message='Email must not exceed 120 characters')
        ],
        render_kw={'placeholder': 'Enter email', 'class': 'form-control', 'type': 'email'}
    )
    
    phone = StringField(
        'Phone',
        validators=[
            DataRequired(message='Phone number is required'),
            Length(min=10, max=20, message='Phone number must be between 10 and 20 characters'),
            Regexp(
                r'^[\d\s\-\+\(\)]+$',
                message='Phone number can only contain digits, spaces, hyphens, plus signs, and parentheses'
            )
        ],
        render_kw={'placeholder': 'Enter phone number', 'class': 'form-control'}
    )
    
    submit = SubmitField('Submit', render_kw={'class': 'btn btn-success btn-lg'})
    
    def validate_phone(self, field):
        """Custom validator to ensure phone has at least 10 digits"""
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', field.data)
        if len(digits_only) < 10:
            raise ValidationError('Phone number must contain at least 10 digits')


class RegistrationForm(FlaskForm):
    """Form for user registration with secure password handling"""
    
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required'),
            Length(min=3, max=50, message='Username must be between 3 and 50 characters'),
            Regexp(
                r'^[A-Za-z0-9_]+$',
                message='Username can only contain letters, numbers, and underscores'
            )
        ],
        render_kw={'placeholder': 'Choose a username', 'class': 'form-control'}
    )
    
    email = StringField(
        'Email',
        validators=[
            DataRequired(message='Email is required'),
            Email(message='Invalid email address'),
            Length(max=120, message='Email must not exceed 120 characters')
        ],
        render_kw={'placeholder': 'Enter your email', 'class': 'form-control', 'type': 'email'}
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required'),
            Length(min=8, max=128, message='Password must be at least 8 characters'),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                message='Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character'
            )
        ],
        render_kw={'placeholder': 'Create a strong password', 'class': 'form-control'}
    )
    
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password'),
            EqualTo('password', message='Passwords must match')
        ],
        render_kw={'placeholder': 'Confirm your password', 'class': 'form-control'}
    )
    
    submit = SubmitField('Register', render_kw={'class': 'btn btn-primary btn-lg'})


class LoginForm(FlaskForm):
    """Form for user login"""
    
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required'),
            Length(min=3, max=50, message='Username must be between 3 and 50 characters')
        ],
        render_kw={'placeholder': 'Enter your username', 'class': 'form-control'}
    )
    
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required')
        ],
        render_kw={'placeholder': 'Enter your password', 'class': 'form-control'}
    )
    
    submit = SubmitField('Login', render_kw={'class': 'btn btn-primary btn-lg'})
