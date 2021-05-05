/*
 * CryptageDecryptage.c
 *
 *  Created on: Nov 7, 2019
 *      Author: Victor
 *
 *Algorithme de cryptage et decryptage
 */


#include <stdio.h>

#include <string.h>

#include <stdlib.h>

// la fonction clef permet de faire a la fois le cryptage de la clef
// ainsi que le cryptage XOR et le cryptage chiffrement de césar du texte contenue dans le fichier texte
// la variable hash nous permet de transformer tout les carracteres du mdp en cryptage XOR
// ensuite on effectue un chiffrement de césar sur le message dans un premier temps
// puis dans un second temps on crypte le message en XOR

void clef(char mdp[50],char text[1024], int decalage)         // fonction pour calculer la clef pour le chiffrage
{
	//variables locaux
	int  i , j , k ;                      // indices des boucles
	char conversion_charactere, conversion_mdp , conversion_XOR ; // characteres pour les conversions
	int Key = 0;                            // calcule de la clef K
	int hash = 0;                         // calcul du hash
	int longueurmdp = strlen (mdp);                 // longeur du mdp
	int longueurtext = strlen(text);                  // longeur du text
	int asci ;                            // code asci
	int asciText ;                        // code asci des characteres du mot de passe

	//calcule du hash entre les characteres
	for ( i = 0 ; i < longueurmdp ; i++)               // boucle conversion string en characteres
	{
		conversion_mdp= mdp[i] ;                          // conversion string en characteres
		asciText = conversion_mdp ;                       // conversion code characteres en code asci
		hash ^= asciText ;                          // calcul du hash
	}
	// cle Key
	Key = hash ^ decalage ; // calcule de la clef Key

	// cryptage cesar
	for ( j = 0 ; text[j] != '\0' ; ++j )     // boucle conversion string en characteres
	{
		conversion_charactere = text[j] ;                            // conversion string en characteres
		asci = conversion_charactere ;
		// pour les characteres minuscules
		if ( asci >= 97 && asci <= 122 )          // condition que les characters sont alphabet
		{
			asci = asci + decalage ;               //  cryptage cesar
			if ( asci > 122)
			{
				asci = asci - 26 ; // si charactere cryptee  est plus que le Z on la retourne comme aplhabet
			}
			conversion_charactere = asci ;
			text[j]= conversion_charactere ;                    // retours en boucle

		}

	// pour les characteres majuscules
	else if ( asci >= 65  && asci  <= 90 )      // condition que les characters sont alphabet
	{
		asci = asci + decalage ;         //  cryptage cesar
		if ( asci > 90)
		{
			asci = asci - 26 ;  // si charactere cryptee  est plus que le Z on la retourne comme aplhabet
		}
		conversion_charactere = asci ;                       // conversion asci en characteres
		text[j]= conversion_charactere ;                      // retours en boucle
		}
	}
	// calcule du XOR
	for (k = 0 ; k < longueurtext ; k++)    //boucle conversion string en characteres
	{
		conversion_XOR = text[k];        // string en characteres
		conversion_XOR = conversion_XOR ^ Key ;      // XOR des characteres avec la clef Key
		text[k]= conversion_XOR ;      // retours en string

	}
}

// la fonction clefd permet de faire a la fois le decryptage de la clef
// ainsi que le decryptage XOR et le decryptage chiffrement de césar du texte crypté contenue dans le fichier texte
// la variable hash nous permet de decryptage clef qui est en XOR pour la remettre en caractère
// ensuite on effectue un XOR sur le message dans un premier temps
// puis dans un second temps on decrypte le message grace au chiffremment de césar pour avoir un teste claire

void clefd (char mdp[50], char text[1024] , int decalage)
{
	//variables locaux
	int  i , j ,k ;                // indices des boucles
	char conversion_charactere, conversion_mdp , conversion_XOR ;// characteres pour les conversions
	int Key = 0;                     // la clef K
	int hash = 0;                  // calcul du hash
	int longueurmdp = strlen (mdp); // longeur du string mdp
	int longueurtext = strlen(text);           // longeur du string ces
	int asci ;                     // code asci
	int asciText ;
	// code asci des characteres du mot de passe
	//calcule du hash entre les characteres
	for ( i = 0 ; i < longueurmdp ; i++)  // boucle  conversion string en characteres
	{
		conversion_mdp= mdp[i] ;             // string en characteres
		asciText = conversion_mdp;           // characteres en code asci
		hash ^= asciText ;      // hash( XOR entre les characteres du mdp)
	}

	// le calcule du K
	Key = hash ^ decalage ;  //calcul de la clef K

	// cryptage XOR des characteres du text
	for (k = 0 ; k < longueurtext ; k++)  // boucle  conversion string en characteres
	{
		conversion_XOR = text[k];      // string en characteres
		conversion_XOR = conversion_XOR ^ Key ;     // XOR de chaque characteres du text et la clef K
		text[k]= conversion_XOR ;      // retours du code cryptee en string
	}
   //decryptage du code cesar
	for ( j = 0 ; text[j] != '\0' ; ++j ) // boucle conversion string en characteres
	{
		conversion_charactere = text[j] ;  // string en characteres
		asci = conversion_charactere;

		// pour les charactere minuscules
		if ( asci >= 97  && asci <= 122 )       // condition que les characters sont des alphabetes
		{
			asci = asci - decalage ;          // decryptage cesar des codes asci
			if ( asci < 97)
			{
				asci = asci + 26 ;  // si le code asci  est moins de a on la retourne en alphabet
			}
			conversion_charactere = asci ;                // conversion asci en characteres
            text[j]= conversion_charactere ;              // retour en boucle
		}

		// pour les characteres majuscules
		else if ( asci >= 65   && asci  <= 90 ) // condition que les characters sont des alphabetes
		{
			asci = asci - decalage ;              // decryptage cesar des codes asci
			if ( asci < 65)
			{
				asci = asci + 26 ; // si le code asci  est moins de a on la retourne en alphabet
			}
			conversion_charactere= asci ;                    // conversion asci en characteres
			text[j]=conversion_charactere;                  // retour en boucle
		}
	}
}



// fonction encrypt
// on propose a l'utilisateur deux élément a crypter soir un fichier existant soit de crypter sa chaine de caractère
// une fois cette etape faite on demande a l'utilisateur d'écrire le nom du fichier existant, puis le decalage et le mot de passe
//et ensuite on ouvre un autre fichier et on insert le message crypter par la fonction clef
// dans l'autres cas on demande a l'utilisateur de creer son fichier texte, puis d'inserer sont message, ensuite on

void encrypt (char text[1024],char mdp[50])
{
    // variables locaux
		char newfichier[100];
	    char nomfichier[100];// nom du fichier =
	    int choix3 ;// choix de type de lecture
	    int decalage;



        FILE * fichier;
        FILE * claire;

        printf("---------------------------------------------------------------------------------------------------------\n");

        printf("\nVoulez-vous:\n"); // choix méthode cryptage

                printf("\n2:crypter un fichier existant? \n");
                printf("\n3:Ou Ecrire la chaine de caracteres?\n\n");
                scanf("%d", &choix3);

        printf("---------------------------------------------------------------------------------------------------------\n");

        switch(choix3)
        {
        case 2 :

            printf("\ninserez le nom du fichier txt existant\n\n");
            scanf("%s", nomfichier);
            fichier = fopen(nomfichier,"r+");

            printf("\ninserez un decallage\n\n");
            scanf("%d", &decalage);

            //condition mauvaise ou bonne lecture
            if ( fichier == NULL )
                {
                    printf("echec creation fichier\n\n");
                    exit(1);
                    }
                fscanf(fichier,"%s",text);// lecture du string depuits le fichier txt
                printf("\nNomez le fichier de la sauvegarde\n\n");
                            scanf("%s", newfichier);

                            //ouvrir le fichier txt
                            fichier = fopen(newfichier,"w+");

                            //condition mauvaise ou bonne lecture
                            if ( fichier == NULL )
                                    {
                                         printf("echec creation fichier\n");

                                    }
                                 printf("inserez votre mot de passe\n\n");
                                        scanf("%s" ,mdp);

                        clef(mdp,text,decalage);
                        fprintf(fichier,"%s", text);
                        fclose(fichier);
                        printf("---------------------------------------------------------------------------------------------------------\n");

                        break;
        case 3:
        {
            printf("\nNomez le fichier de la sauvegarde\n\n");
            scanf("%s", newfichier);
                    //ouvrir le fichier txt
                fichier = fopen(newfichier,"w+");
                claire = fopen("textclaire.txt","w");
                //condition mauvaise ou bonne lecture
                 if ( fichier == NULL )
                    {
                         printf("echec creation fichier\n\n");

                    }
                 printf("\ninserez- votre texte\n\n");
                 getchar();
                 gets(text);
                 fprintf(claire,"voila le texte claire :%s",text);

                 printf("\ninserez un decallage\n\n");
                 scanf("%d", &decalage);
                 printf("\ninserez votre mot de passe\n\n");
                 scanf("\n%s" ,mdp);
                 clef(mdp,text,decalage);
        fprintf(fichier,"%s", text);
        fclose(fichier);
        printf("---------------------------------------------------------------------------------------------------------\n");

        }
     }
}

// fonction decrypt
// on permet a l'utilisateur de choisir s'il veut decrypter un fichier exterieur
// ou si on veut decrypter le message  qu'on a cryter juste avant
// d'abord on a demande le nom du fichier a decrypter puis on demande le decalage, puis on demande de donner un nom au fichier txt
// qui va contenir le message decrypter
// puis la fonction clefd decrypt et le message decrypter est inserez dans le fichier
// dans l'autre cas on demande a l'utilisateur de rentrer le message crypter puis on demande le decalage et on creer un fichier
// qui va contenir le message decrypter
// la fonction clefd decrypte le message et le message est ecrit dans le fichier creer juste avant

void decrypt(char text[1024], char mdp[50])
{
    // variables locaux

    char newfichier[100];
    char nomfichier[100];// nom du fichier
    int choix4 ;// choix de type de lecture
    int decalage;



    FILE * fichier;

    printf("---------------------------------------------------------------------------------------------------------\n");

    printf("\nVoulez-vous:\n"); // choix méthode cryptage
                printf("\n4:decrypter fichier exterieur? \n");
                printf("\n5:decrypter votre chaine de carractere?\n\n");
                scanf("%d", &choix4);

    printf("---------------------------------------------------------------------------------------------------------\n");
    switch(choix4)
    {
    case 4:

        printf("\ninserez le nom de votre fichier\n\n");
        scanf("%s", nomfichier);
    fichier = fopen(nomfichier,"r");
    //condition mauvaise ou bonne lecture
                    if ( fichier == NULL )
                        {
                             printf("echec ouverture fichier\n\n");
                        }
    fscanf(fichier,"%s",text );
    printf("voici le message a decrypter %s\n\n", text);

    printf("\ninserez un decallage\n\n");
            scanf("%d", &decalage);

    printf("\nNomez le fichier de sauvegarde\n\n");
            scanf("%s" , newfichier);

            //ouvrir le fichier txt
            fichier = fopen(newfichier,"w+");

            //condition mauvaise ou bonne lecture
            if ( fichier == NULL )
                {
                    printf("echec creation fichier\n\n");
                }
            printf("\ninserez votre mot de passe\n\n");
            scanf("%s" ,mdp);
            clefd(mdp,text,decalage);
            fprintf(fichier,"%s", text);
            fclose(fichier);
            printf("---------------------------------------------------------------------------------------------------------\n");

            break;

    case 5:

            printf("\ninserez-votre mot message cryptee\n\n");
            scanf("%s", text);

            printf("\ninserez un decalage\n\n");
            scanf("%d", &decalage);

            printf("\nNomez le fichier de sauvegarde\n\n");
            scanf("%s" , newfichier);

            //ouvrir le fichier txt
            fichier = fopen(newfichier,"w");

            //condition mauvaise ou bonne lecture
            if ( fichier == NULL )
                {
                    printf("echec creation fichier\n\n");
                }
            printf("\ninserez votre mot de passe\n\n");
            scanf("%s" ,mdp);

            clefd(mdp,text,decalage);
            fprintf(fichier,"voici le message decypte est : %s", text);
            fclose(fichier);
            printf("---------------------------------------------------------------------------------------------------------\n");

            break;
    }
}

// main
// j'ai d'abord creer une boucle "tant que" qui ne s'arrete pas tant que l'utilisateur n'exécute pas 0
// puis je creer un switch qui me permet de demander a l'utilisateur s'il veut crypter ou decrypter
// on fonction du choix fait le programme run la fonction encrypt ou decrypt

int main(void)
{
    // variables
    char text[1024] ;// message
    char mdp[50]; // mot de passe
    char  choix;
    int choix2; // choix de decryptage ou de decryptage

    printf("-----------------------------------------------------------------------------------------------------------------------\n");
    printf("Bienvenue dans le programme de cryptage et decryptage\n");
    printf("------------------------------------------------------------------------------------------------------------------------\n");


    printf("Voulez-vous commencer ou recommencer?(o/n)\n\n");
    scanf("%c",&choix);
    while (choix=='o')
        {
        printf("\nCryptage et decryptage de fichiers texte\n");
        printf("\nVoulez vous encrypter ou decrypter:\n");
        printf("\n0:quitter\n");
        printf("\n1: encrypter\n");
        printf("\n2: decrypter\n\n");
        scanf("%d",&choix2);

        if (choix2==0)
        {
        	printf("vous avez quitte");
            return 0;
        }

       if(choix2==1)
       {
            encrypt(text,mdp);
            printf("voici le code cryptee: %s\n\n", text);
       }
       if(choix2==2)
       {
            decrypt(text,mdp);
            printf("voici le code decryptee: %s\n\n", text);
       }

       }
   system("pause");
}
