// Copyright IBM Corp. 2018,2019. All Rights Reserved.
// Node module: loopback4-example-shopping
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT
import {
  post, param, get, requestBody, HttpErrors,
  getFilterSchemaFor,
  getModelSchemaRef,
  getWhereSchemaFor,
  patch,
  put,
  del,
} from '@loopback/rest';
import {
  Count,
  CountSchema,
  Filter,
  repository,
  Where,
} from '@loopback/repository';
import { validateCredentials } from '../services/validator';
import { User } from '../models';
import { UserRepository } from '../repositories';
import { inject } from '@loopback/core';
import {
  authenticate,
  UserProfile,
  AuthenticationBindings,
  TokenService,
  UserService,
} from '@loopback/authentication';
import {
  CredentialsRequestBody,
} from './specs/user-controller.specs';
import { Credentials } from '../repositories/user.repository';
import { PasswordHasher } from '../services/hash.password.bcryptjs';

import {
  TokenServiceBindings,
  PasswordHasherBindings,
  UserServiceBindings,
} from '../keys';

const _ = require('lodash');

export class UserController {
  constructor(
    @repository(UserRepository) public userRepository: UserRepository,
    @inject(PasswordHasherBindings.PASSWORD_HASHER)
    public passwordHasher: PasswordHasher,
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: TokenService,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: UserService<User, Credentials>,
  ) { }

  @del('/users/{id}', {
    responses: {
      '204': {
        description: 'User DELETE success',
      },
    },
  })
  async deleteById(@param.path.string('id') id: string): Promise<User> {
    let usr = this.userRepository.findById(id, {
      fields: { password: false },
    });
    await this.userRepository.deleteById(id);
    return usr;
  }

  @patch('/users', {
    responses: {
      '200': {
        description: 'User PATCH success count',
        content: { 'application/json': { schema: CountSchema } },
      },
    },
  })
  async updateAll(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(User, { partial: true }),
        },
      },
    })
    user: User,
    @param.query.object('where', getWhereSchemaFor(User)) where?: Where<User>,
  ): Promise<Count> {
    return this.userRepository.updateAll(user, where);
  }

  @post('/users', {
    responses: {
      '200': {
        description: 'User',
        content: { 'application/json': { schema: getModelSchemaRef(User) } },
      },
    },
  })
  async create(@requestBody({
    content: {
      'application/json': {
        schema: getModelSchemaRef(User),
      },
    },
  })
  user: User,
  ): Promise<User> {
    // ensure a valid email value and password value
    validateCredentials(_.pick(user, ['email', 'password']));

    // encrypt the password
    // eslint-disable-next-line require-atomic-updates
    user.password = await this.passwordHasher.hashPassword(user.password);

    try {
      // create the new user
      const savedUser = await this.userRepository.create(user);
      delete savedUser.password;

      return savedUser;
    } catch (error) {
      // MongoError 11000 duplicate key
      if (error.code === 11000 && error.errmsg.includes('index: uniqueEmail')) {
        throw new HttpErrors.Conflict('Email value is already taken');
      } else {
        throw error;
      }
    }
  }

  @get('/users/count', {
    responses: {
      '200': {
        description: 'User model count',
        content: { 'application/json': { schema: CountSchema } },
      },
    },
  })
  async count(
    @param.query.object('where', getWhereSchemaFor(User)) where?: Where<User>,
  ): Promise<Count> {
    return this.userRepository.count(where);
  }



  @get('/users/{userId}', {
    responses: {
      '200': {
        description: 'User',
        content: {
          'application/json': {
            schema: {
              'x-ts-type': User,
            },
          },
        },
      },
    },
  })
  async findById(@param.path.string('userId') userId: string): Promise<User> {
    return this.userRepository.findById(userId, {
      fields: { password: false },
    });
  }



  @post('/users/login/{userId}', {
    responses: {
      '200': {
        description: 'User',
        content: { 'application/json': { schema: getModelSchemaRef(User) } },
      },
    },
  })
  async signup(@requestBody({
    content: {
      'application/json': {
        schema: getModelSchemaRef(User),
      },
    },
  })
  user: User,
    @param.path.string('userId') userId: string): Promise<User | null | undefined> {

    const usr = this.userRepository.findOne({ where: { _id: userId } });

    if (usr) {

      validateCredentials(_.pick(user, ['email', 'password']));

      user.password = await this.passwordHasher.hashPassword(user.password);

      try {
        const savedUser = await this.userRepository.create(user);
        delete savedUser.password;

        return savedUser;
      } catch (error) {
        if (error.code === 11000 && error.errmsg.includes('index: uniqueEmail')) {
          throw new HttpErrors.Conflict('Email value is already taken');
        } else {
          throw error;
        }
      }

    }
    else {
      return usr;
    }

  }







  @get('/users', {
    responses: {
      '200': {
        description: 'Array of User model instances',
        content: {
          'application/json': {
            schema: { type: 'array', items: getModelSchemaRef(User) },
          },
        },
      },
    },
  })
  async find(
    @param.query.object('filter', getFilterSchemaFor(User)) filter?: Filter<User>,
  ): Promise<User[]> {

    return this.userRepository.find(filter);
  }


  @get('/users/me', {
    responses: {
      '200': {
        description: 'The current user profile',
        content: {
          'application/json': {
            schema: { type: 'array', items: getModelSchemaRef(User) },
          },
        },
      },
    },
  })
  @authenticate('jwt')
  async printCurrentUser(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUserProfile: UserProfile,
  ): Promise<UserProfile> {
    return currentUserProfile;
  }




  @post('/users/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody(CredentialsRequestBody) credentials: Credentials,
  ): Promise<{ token: string }> {
    // ensure the user exists, and the password is correct
    const user = await this.userService.verifyCredentials(credentials);

    // convert a User object into a UserProfile object (reduced set of properties)
    const userProfile = this.userService.convertToUserProfile(user);

    // create a JSON Web Token based on the user profile
    const token = await this.jwtService.generateToken(userProfile);

    return { token };
  }



}
