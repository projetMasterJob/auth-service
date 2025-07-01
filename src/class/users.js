class User {
  constructor(id, first_name, last_name, email, password, address, phone, role, created_at) {
    this.id = id;
    this.first_name = first_name;
    this.last_name = last_name;
    this.email = email;
    this.password = password; // Note: In a real application, never store passwords in plain text
    this.address = address;
    this.phone = phone;
    this.role = role; // e.g., 'user', 'admin'
    this.created_at = created_at; // Date of creation
  }
}