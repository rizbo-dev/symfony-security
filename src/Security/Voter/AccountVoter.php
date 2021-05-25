<?php

namespace App\Security\Voter;

use App\Entity\Account;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;

class AccountVoter extends Voter
{
    public function __construct(public Security $security)
    {
        
    }
    
    protected function supports(string $attribute, $subject): bool
    {
        // replace with your own logic
        // https://symfony.com/doc/current/security/voters.html
        return in_array($attribute, ['SHOW', 'DELETE'])
            && $subject instanceof \App\Entity\Account;
    }

    /**
     * @param string $attribute
     * @param Account $subject
     * @param TokenInterface $token
     * @return bool
     */

    protected function voteOnAttribute(string $attribute, $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        // if the user is anonymous, do not grant access
        if (!$user instanceof UserInterface) {
            return false;
        }

        $accessIsGranted = match ($attribute) {
            'SHOW' => $this->show($subject,$user),
            'DELETE' => $this->security->isGranted('ROLE_ADMIN')
        };

        return $accessIsGranted;
    }

    private function show($subject, $user)
    {
        return $subject->getAccountHolder() === $user
            || $subject->getAccountManager() === $user
            || $this->security->isGranted('ROLE_ADMIN');
    }
}
