export interface Profile {
  id: string
  email: string
  name: string
  avatar_url?: string
  is_admin: boolean
  first_name?: string
  middle_name?: string
  surname?: string
  date_of_birth?: string
  gender?: string
  created_at: string
}

export interface Letter {
  id: number
  user_id: string
  nickname?: string
  name: string
  to_country: string
  from_country: string
  sent_date?: string
  received_date?: string
  days?: number
  tracking?: string
  letter_type: 'Sending' | 'Receiving'
  is_completed: boolean
  status: string
  attachment_url?: string
  source_id?: number
  created_at: string
}

export interface Source {
  id: number
  user_id: string
  name: string
  link?: string
  created_at: string
}

export interface Address {
  id: number
  user_id: string
  title: string
  full_address: string
  country: string
  city?: string
  zip_code?: string
  is_default: boolean
  created_at: string
}
