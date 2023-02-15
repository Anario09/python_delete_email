import os
import pickle
import base64
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.errors import HttpError
from googleapiclient.discovery import build

# Définit les scopes pour l'API Gmail
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Fonction pour obtenir les informations d'identification de l'utilisateur et accéder à l'API Gmail
def get_gmail_service():
    # Vérifie si les informations d'identification de l'utilisateur sont déjà enregistrées dans un fichier pickle
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # Si les informations d'identification de l'utilisateur ne sont pas enregistrées ou ont expiré, demande une nouvelle autorisation à l'utilisateur
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Enregistre les informations d'identification de l'utilisateur pour une utilisation ultérieure
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    # Crée le service Gmail avec les informations d'identification de l'utilisateur
    service = build('gmail', 'v1', credentials=creds)
    return service

# Fonction pour supprimer tous les e-mails d'un expéditeur donné
def supprimer(expediteur):
    service = get_gmail_service()
    query = "from:" + expediteur
    try:
        # Recherche tous les e-mails de l'expéditeur donné
        response = service.users().messages().list(userId='me', q=query).execute()
        messages = response['messages']
        # Supprime tous les e-mails trouvés
        for message in messages:
            service.users().messages().trash(userId='me', id=message['id']).execute()
        print(f"Tous les e-mails de {expediteur} ont été supprimés avec succès.")
    except HttpError as error:
        print(f'Une erreur s\'est produite : {error}')

# Fonction pour récupérer l'adresse email d'un expéditeur à partir d'un message donné
def get_sender_from_message(message):
    headers = message['payload']['headers']
    for header in headers:
        if header['name'] == 'From':
            return header['value']
    return None

# Fonction pour supprimer tous les e-mails d'un expéditeur donné à partir d'une liste de messages donnée
def supprimer_messages(expediteur, messages):
    service = get_gmail_service()
    for message in messages:
        sender = get_sender_from_message(message)
        if sender == expediteur:
            service.users().messages().trash(userId='me', id=message['id']).execute()
            print(f"L'e-mail de {sender} a été supprimé avec succès.")
    print(f"Tous les e-mails de {expediteur} ont été supprimés avec succès.")

# Exemple d'utilisation
expediteur = 'example@twitch.tv'
service = get_gmail_service()
query = "from:" + expediteur
response = service.users().messages().list(userId='me', q=query).execute()
messages = response['messages']
