using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using RuntimeApps.Authentication.Interface;
using RuntimeApps.Authentication.Model;

namespace RuntimeApps.Authentication.Controller {
    public abstract class BaseUserController<TUser, TUserDto>: ControllerBase 
        where TUser: class
        where TUserDto: class{
        private readonly IUserManager<TUser> _userManager;
        private readonly IMapper _mapper;

        protected BaseUserController(IUserManager<TUser> userManager, IMapper mapper) {
            _userManager = userManager;
            _mapper = mapper;
        }

    }
}
