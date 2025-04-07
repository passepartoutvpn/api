//
//  nordvpn.js
//  PassepartoutKit
//
//  Created by Davide De Rosa on 3/28/25.
//  Copyright (c) 2025 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of PassepartoutKit.
//
//  PassepartoutKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  PassepartoutKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with PassepartoutKit.  If not, see <http://www.gnu.org/licenses/>.
//

function getInfrastructure() {
    const json = getJSON("https://raw.githubusercontent.com/passepartoutvpn/api-cache/refs/heads/master/v6/providers/nordvpn/fetch.json");
    if (json.error) {
        return json;
    }
    json.response.cache = json.cache;
    return json;
}
