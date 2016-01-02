/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.brekka.phalanx.core.services;

import java.util.UUID;

import org.brekka.phalanx.api.model.AuthenticatedPrincipal;
import org.brekka.phalanx.api.model.ExportedPrincipal;
import org.brekka.phalanx.core.model.Principal;

public interface PrincipalService {

    Principal createPrincipal(String password);

    AuthenticatedPrincipal authenticate(Principal user, String password);

    Principal retrieveById(UUID principalId);

    void deletePrincipal(UUID principalId);

    ExportedPrincipal export(AuthenticatedPrincipal principal, byte[] secret);

    AuthenticatedPrincipal restore(ExportedPrincipal exportedPrincipal, byte[] secret);
}
