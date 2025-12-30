"""
SecureIT - Password Validator Module
Validates password strength and provides recommendations
"""

import re
from typing import List, Tuple


class PasswordValidator:
    """
    Validates password strength and provides feedback
    """
    
    # Common weak passwords to check against
    COMMON_PASSWORDS = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321'
    ]
    
    def __init__(self):
        self.min_length = 8
        self.recommended_length = 12
        
    def calculate_strength(self, password: str) -> int:
        """
        Calculate password strength score (0-100)
        
        Args:
            password: Password to evaluate
            
        Returns:
            Strength score from 0 (weakest) to 100 (strongest)
        """
        if not password:
            return 0
            
        score = 0
        
        # Length scoring (up to 30 points)
        length = len(password)
        if length >= 8:
            score += 10
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10
            
        # Character diversity (up to 40 points)
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            score += 10
            
        # Complexity bonus (up to 20 points)
        unique_chars = len(set(password))
        if unique_chars >= length * 0.5:
            score += 10
        if unique_chars >= length * 0.75:
            score += 10
            
        # Check for common passwords (penalty)
        if password.lower() in self.COMMON_PASSWORDS:
            score = max(0, score - 30)
            
        # Check for repeated characters (penalty)
        if re.search(r'(.)\1{2,}', password):
            score = max(0, score - 10)
            
        # Check for sequential characters (penalty)
        if self._has_sequential_chars(password):
            score = max(0, score - 10)
            
        return min(100, score)
        
    def _has_sequential_chars(self, password: str) -> bool:
        """Check if password contains sequential characters"""
        sequences = ['abc', '123', 'xyz', '789', 'qwe', 'asd', 'zxc']
        password_lower = password.lower()
        
        for seq in sequences:
            if seq in password_lower:
                return True
        return False
        
    def validate_password(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password and provide recommendations
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list of recommendations)
        """
        recommendations = []
        
        if not password:
            return False, ["Password is required"]
            
        # Check minimum length
        if len(password) < self.min_length:
            recommendations.append(f"Password must be at least {self.min_length} characters long")
            return False, recommendations
            
        # Provide recommendations for improvement
        if len(password) < self.recommended_length:
            recommendations.append(f"Consider using at least {self.recommended_length} characters for better security")
            
        if not re.search(r'[a-z]', password):
            recommendations.append("Add lowercase letters (a-z)")
            
        if not re.search(r'[A-Z]', password):
            recommendations.append("Add uppercase letters (A-Z)")
            
        if not re.search(r'\d', password):
            recommendations.append("Add numbers (0-9)")
            
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            recommendations.append("Add special characters (!@#$%^&* etc.)")
            
        if password.lower() in self.COMMON_PASSWORDS:
            recommendations.append("This is a commonly used password. Choose something more unique")
            
        if re.search(r'(.)\1{2,}', password):
            recommendations.append("Avoid repeated characters (e.g., 'aaa', '111')")
            
        if self._has_sequential_chars(password):
            recommendations.append("Avoid sequential characters (e.g., 'abc', '123')")
            
        # Password is valid if it meets minimum requirements
        is_valid = len(password) >= self.min_length
        
        return is_valid, recommendations
        
    def get_strength_label(self, score: int) -> str:
        """
        Get text label for strength score
        
        Args:
            score: Strength score (0-100)
            
        Returns:
            Label string ('Weak', 'Medium', 'Strong')
        """
        if score < 40:
            return "Weak"
        elif score < 70:
            return "Medium"
        else:
            return "Strong"
            
    def get_strength_color(self, score: int) -> str:
        """
        Get color for strength score
        
        Args:
            score: Strength score (0-100)
            
        Returns:
            Color string ('red', 'orange', 'green')
        """
        if score < 40:
            return "red"
        elif score < 70:
            return "orange"
        else:
            return "green"
            
    def generate_password(self, length: int = 16) -> str:
        """
        Generate a strong random password
        
        Args:
            length: Desired password length
            
        Returns:
            Generated password
        """
        import secrets
        import string
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill remaining length with random characters from all sets
        all_chars = lowercase + uppercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        
        return ''.join(password_list)


# Test function
def test_password_validator():
    """Test password validator functionality"""
    validator = PasswordValidator()
    
    test_passwords = [
        "weak",
        "password123",
        "StrongP@ss123",
        "MyV3ry$tr0ng&P@ssw0rd!",
        "12345678",
        "Abcd1234!",
    ]
    
    print("Testing Password Validator\n")
    print("=" * 60)
    
    for pwd in test_passwords:
        score = validator.calculate_strength(pwd)
        label = validator.get_strength_label(score)
        color = validator.get_strength_color(score)
        is_valid, recommendations = validator.validate_password(pwd)
        
        print(f"\nPassword: {pwd}")
        print(f"Score: {score}/100")
        print(f"Strength: {label} ({color})")
        print(f"Valid: {is_valid}")
        
        if recommendations:
            print("Recommendations:")
            for rec in recommendations:
                print(f"  - {rec}")
                
    # Test password generation
    print("\n" + "=" * 60)
    print("\nGenerated Strong Passwords:")
    for i in range(3):
        generated = validator.generate_password(16)
        score = validator.calculate_strength(generated)
        print(f"  {generated} (Score: {score}/100)")
        
    print("\nTest completed!")


if __name__ == "__main__":
    test_password_validator()